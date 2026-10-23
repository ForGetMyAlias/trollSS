//! лезем в джаву через её сокет attach (протокол jcmd, JDK не нужен): все загруженные классы, загрузчики классов,
//! границы JIT кэша и стеки потоков. ещё смотрим стеки нативных потоков (только с root).
//! при подключении остаётся след (сокет .java_pid), чтобы не подключаться запускай с --passive.
use super::classes::{judge, known, runtime_class, vocab_findings};
use super::maps::{Trust, anon_exec_suspects, jdk_root, trust};
use crate::model::*;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

pub struct Jvm;

fn attach(pid: u32, cmd: &str) -> Result<String, String> {
    let sock = format!("/tmp/.java_pid{pid}");
    if !Path::new(&sock).exists() {
        let trig = [
            format!("/proc/{pid}/cwd/.attach_pid{pid}"),
            format!("/tmp/.attach_pid{pid}"),
        ];
        let used = trig
            .iter()
            .find(|t| std::fs::File::create(t).is_ok())
            .ok_or("cannot create attach trigger file")?;
        // SAFETY: SIGQUIT это нормальный способ разбудить attach listener в HotSpot
        unsafe { libc::kill(pid as i32, libc::SIGQUIT) };
        for _ in 0..50 {
            if Path::new(&sock).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = std::fs::remove_file(used);
    }
    let mut s = UnixStream::connect(&sock).map_err(|e| format!("connect {sock}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    s.write_all(format!("1\0jcmd\0{cmd}\0\0\0").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    s.read_to_end(&mut out).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out).into_owned();
    match text.split_once('\n') {
        Some((code, rest)) if code.trim() == "0" => Ok(rest.to_string()),
        Some((code, rest)) => Err(format!(
            "{cmd}: status {} {}",
            code.trim(),
            rest.lines().next().unwrap_or("")
        )),
        None => Err(format!("{cmd}: empty reply")),
    }
}

fn hex(s: &str) -> Option<u64> {
    u64::from_str_radix(
        s.trim_matches(|c| c == ',' || c == '[' || c == ']')
            .trim_start_matches("0x"),
        16,
    )
    .ok()
}

impl Check for Jvm {
    fn name(&self) -> &'static str {
        "JVM internals"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("jvm");
        let Some(pid) = ctx.pid else {
            o.add(Sev::Info, "no Minecraft process — skipped");
            return o.v;
        };
        let regs = ctx.maps();
        let mut jit: Option<Vec<(u64, u64)>> = None;

        if !std::env::args().any(|a| a == "--passive") {
            match attach(pid, "Compiler.codecache") {
                Ok(t) => {
                    let v: Vec<(u64, u64)> = t
                        .lines()
                        .filter(|l| l.trim_start().starts_with("bounds"))
                        .filter_map(|l| {
                            let n: Vec<u64> =
                                l.split_whitespace().skip(1).filter_map(hex).collect();
                            Some((*n.first()?, *n.get(2)?))
                        })
                        .collect();
                    jit = Some(v);
                }
                Err(e) => o.add(
                    Sev::Info,
                    format!("JVM attach unavailable ({e}); using heuristics"),
                ),
            }
            set_pct(pct, 1, 10);
            if jit.is_some() {
                let loaders = attach(pid, "VM.classloader_stats").unwrap_or_default();
                let mut cld_name: HashMap<String, String> = HashMap::new();
                let (known, _) = known(ctx);
                for l in loaders.lines() {
                    let t: Vec<&str> = l.split_whitespace().collect();
                    if t.len() < 7 || !t[0].starts_with("0x") {
                        continue;
                    }
                    let ty = t[6..].join(" ");
                    cld_name.insert(t[2].to_string(), ty.clone());
                    let slash = ty.replace('.', "/");
                    let classes: u32 = t[3].parse().unwrap_or(0);
                    if ty.starts_with('<') || classes == 0 {
                        continue;
                    }
                    if !known.contains(&slash) && !runtime_class(&slash) {
                        o.add(Sev::Crit, format!("class loader implemented by a class that is in no jar: {ty} ({classes} classes)"));
                    } else if ty == "java.net.URLClassLoader"
                        || ty == "java.security.SecureClassLoader"
                    {
                        o.add(Sev::Warn, format!("extra {ty} holding {classes} classes (injected jars are often loaded this way)"));
                    }
                }
                set_pct(pct, 3, 10);

                let mut seen: HashSet<String> = HashSet::new();
                let mut by_loader: HashMap<String, Vec<String>> = HashMap::new();
                for l in attach(pid, "VM.class_hierarchy")
                    .unwrap_or_default()
                    .lines()
                {
                    let t = l.trim_start_matches(['|', '-', ' ']);
                    let Some((name, rest)) = t
                        .split_whitespace()
                        .next()
                        .and_then(|tok| tok.split_once('/'))
                    else {
                        continue;
                    };
                    if name.starts_with('[') {
                        continue;
                    }
                    let loader = rest.rsplit('/').next().unwrap_or("").to_string();
                    // boot и platform загрузчики держат только классы самой джавы, их нет ни в одном jar
                    if loader == "null"
                        || cld_name.get(&loader).is_some_and(|n| {
                            n.starts_with("jdk.internal.loader.ClassLoaders$Platform")
                        })
                    {
                        continue;
                    }
                    let slash = name.replace('.', "/");
                    by_loader.entry(loader).or_default().push(slash.clone());
                    seen.insert(slash);
                }
                set_pct(pct, 6, 10);
                for l in attach(pid, "Thread.print").unwrap_or_default().lines() {
                    if let Some(f) = l.trim_start().strip_prefix("at ") {
                        let f = f.split('(').next().unwrap_or("");
                        let f = f.split("/0x").next().unwrap_or(f);
                        let f = f.rsplit_once('/').map_or(f, |x| x.1);
                        if let Some((cls, _)) = f.rsplit_once('.') {
                            seen.insert(cls.replace('.', "/"));
                        }
                    }
                }
                vocab_findings(
                    &mut o,
                    seen.iter().filter(|n| !runtime_class(n)).cloned(),
                    "among classes loaded in the JVM",
                );
                let unknown: HashSet<String> = judge(
                    &mut o,
                    &seen,
                    known,
                    "loaded in the JVM (full class list + thread stacks)",
                )
                .into_iter()
                .collect();
                for (addr, names) in &by_loader {
                    let n = names.iter().filter(|n| unknown.contains(*n)).count();
                    if n > 0 {
                        o.add(
                            Sev::Warn,
                            format!(
                                "{n} unknown classes were defined by loader {}",
                                cld_name.get(addr).map_or(addr.as_str(), |s| s.as_str())
                            ),
                        );
                    }
                }
            }
        }

        let suspects = anon_exec_suspects(&regs, jit.as_deref());
        for (sev, m) in suspects {
            o.add(sev, m);
        }
        set_pct(pct, 8, 10);
        if ctx.root {
            sample_stacks(ctx, &regs, jit.as_deref(), &mut o);
        }
        o.v
    }
}

/// смотрим стек каждого потока: нет ли там адресов возврата в коде которому там не место:
/// удалённые или безфайловые либы, анонимная исполняемая память вне JIT, либы из временных папок.
fn sample_stacks(ctx: &Ctx, regs: &[Region], jit: Option<&[(u64, u64)]>, o: &mut Out) {
    let (Some(pid), Some(mem)) = (ctx.pid, ctx.mem()) else {
        return;
    };
    let jdk = jdk_root(regs);
    let in_jit = |a: u64| jit.is_some_and(|j| j.iter().any(|&(lo, hi)| a >= lo && a < hi));
    let tids: Vec<String> = std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut reported: HashSet<(String, String)> = HashSet::new();
    for _ in 0..8 {
        for tid in &tids {
            let sc = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/syscall"))
                .unwrap_or_default();
            let f: Vec<&str> = sc.split_whitespace().collect();
            let Some(sp) = f
                .len()
                .checked_sub(2)
                .and_then(|i| f.get(i))
                .and_then(|x| hex(x))
            else {
                continue;
            };
            let mut buf = vec![0u8; 64 << 10];
            let Ok(n) = mem.read_at(&mut buf, sp) else {
                continue;
            };
            for q in buf[..n].chunks_exact(8) {
                let a = u64::from_le_bytes(q.try_into().unwrap());
                let i = regs.partition_point(|r| r.end <= a);
                let Some(r) = regs
                    .get(i)
                    .filter(|r| r.start <= a && r.x() && !r.path.starts_with('['))
                else {
                    continue;
                };
                let (sev, what) = if r.anon() {
                    if in_jit(a) || (jit.is_none() && r.size() >= 64 << 10) {
                        continue;
                    }
                    (
                        Sev::Crit,
                        "anonymous executable memory outside the JIT code cache".to_string(),
                    )
                } else {
                    match trust(&r.path, ctx, &jdk) {
                        Trust::System | Trust::Benign => continue,
                        Trust::Staging
                            if r.path.ends_with("(deleted)") || r.path.starts_with("/memfd:") =>
                        {
                            (Sev::Crit, format!("deleted/fileless library {}", r.path))
                        }
                        _ => (Sev::Warn, format!("library {}", r.path)),
                    }
                };
                let comm = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                // служебные потоки джавы гоняют только код джавы. если на стеке чужая либа, значит её подгрузили через этот поток
                let internal = [
                    "Attach Listener",
                    "VM Thread",
                    "Signal Dispatch",
                    "Service Thread",
                    "Reference Handl",
                    "Finalizer",
                    "C1 Compiler",
                    "C2 Compiler",
                    "Monitor Deflat",
                    "VM Periodic",
                    "G1 ",
                    "GC ",
                ]
                .iter()
                .any(|p| comm.starts_with(p));
                let sev = if internal && !r.anon() {
                    Sev::Crit
                } else {
                    sev
                };
                if reported.insert((comm.clone(), what.clone())) {
                    o.add(
                        sev,
                        format!("thread '{comm}' (tid {tid}) has a return address in {what}"),
                    );
                }
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}
