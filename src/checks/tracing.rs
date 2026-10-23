//! кто сейчас лезет в джаву: ptrace, те кто пишет в /proc/PID/mem, процессы без файла или скрытые, дебаггеры и инжекторы, скрытые модули ядра
use crate::model::*;
use std::fs;
use std::sync::atomic::AtomicU32;

pub struct Tracing;

const TOOLS: &[&str] = &[
    "gdb",
    "gdbserver",
    "lldb",
    "strace",
    "ltrace",
    "frida",
    "frida-server",
    "frida-helper",
    "radare2",
    "r2",
    "pwndbg",
    "bpftrace",
];

fn pids() -> Vec<u32> {
    fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

impl Check for Tracing {
    fn name(&self) -> &'static str {
        "Tracing & processes"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("tracing");
        let all = pids();
        let target = ctx.pid;

        if let Some(t) = target {
            if let Ok(rd) = fs::read_dir(format!("/proc/{t}/task")) {
                for tid in rd.flatten() {
                    let st = fs::read_to_string(tid.path().join("status")).unwrap_or_default();
                    let tracer = st
                        .lines()
                        .find_map(|l| l.strip_prefix("TracerPid:"))
                        .map(|v| v.trim().parse::<u32>().unwrap_or(0))
                        .unwrap_or(0);
                    if tracer != 0 {
                        o.add(
                            Sev::Crit,
                            format!(
                                "thread {} traced by PID {tracer} ({})",
                                tid.file_name().to_string_lossy(),
                                comm(tracer)
                            ),
                        );
                    }
                }
            }
            for l in listeners(t) {
                o.add(Sev::Warn, format!("JVM is listening for connections: {l} (command server inside the game process?)"));
            }
            let scope = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
                .unwrap_or_else(|_| "n/a".into());
            o.add(Sev::Info, format!("ptrace_scope={}", scope.trim()));
        }

        for (i, &p) in all.iter().enumerate() {
            set_pct(pct, i as u64, all.len() as u64 * 2);
            if Some(p) == target || p == std::process::id() {
                continue;
            }
            let c = comm(p);
            if TOOLS.contains(&c.as_str()) {
                o.add(
                    Sev::Warn,
                    format!("debugger/injection tool running: {c} (PID {p})"),
                );
            }
            if let Ok(exe) = fs::read_link(format!("/proc/{p}/exe")) {
                let e = exe.to_string_lossy();
                if e.contains("(deleted)") || e.starts_with("/memfd:") {
                    o.add(
                        Sev::Warn,
                        format!("process runs from deleted/fileless binary: PID {p} {c} -> {e}"),
                    );
                }
            }
            // кто держит открытым /proc/PID/mem джавы, тот пишет в неё без ptrace
            if let (Some(t), Ok(fds)) = (target, fs::read_dir(format!("/proc/{p}/fd"))) {
                for fd in fds.flatten() {
                    if let Ok(l) = fs::read_link(fd.path()) {
                        let l = l.to_string_lossy();
                        if l == format!("/proc/{t}/mem")
                            || (l.starts_with(&format!("/proc/{t}/task/")) && l.ends_with("/mem"))
                        {
                            o.add(
                                Sev::Crit,
                                format!("PID {p} ({c}) holds the JVM's memory open: {l}"),
                            );
                        }
                    }
                }
            }
        }

        // скрытые PID: kill(0) говорит что живой, а в /proc его нет. проверяем второй раз чтобы не словить процесс который только что умер
        let max: i32 = fs::read_to_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(32768)
            .min(1 << 22);
        let listed: std::collections::HashSet<u32> = all.iter().copied().collect();
        let hidden: Vec<i32> = (2..max)
            .filter(|&p| !listed.contains(&(p as u32)) && alive(p))
            .collect();
        for p in hidden
            .into_iter()
            .filter(|&p| alive(p) && !std::path::Path::new(&format!("/proc/{p}")).exists())
        {
            o.add(
                Sev::Warn,
                format!("PID {p} exists but is hidden from /proc (hidepid mount or rootkit)"),
            );
        }
        pct.store(90, std::sync::atomic::Ordering::Relaxed);

        // модули ядра которые загружены, но не показаны в /proc/modules
        let listed_mods: std::collections::HashSet<String> = fs::read_to_string("/proc/modules")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_whitespace().next().map(String::from))
            .collect();
        if let Ok(rd) = fs::read_dir("/sys/module") {
            for m in rd.flatten() {
                let n = m.file_name().to_string_lossy().into_owned();
                if m.path().join("initstate").exists() && !listed_mods.contains(&n) {
                    o.add(Sev::Crit, format!("kernel module '{n}' is live in /sys/module but hidden from /proc/modules"));
                }
            }
        }
        if fs::read_dir("/sys/fs/bpf").map(|d| d.count()).unwrap_or(0) > 0 {
            o.add(Sev::Info, "pinned eBPF objects in /sys/fs/bpf");
        }
        o.v
    }
}

fn alive(pid: i32) -> bool {
    // SAFETY: сигнал 0 только проверяет что процесс есть и можно ли ему слать
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// слушающие tcp порты и unix сокеты процесса. игровой клиент обычно ничего не слушает
fn listeners(pid: u32) -> Vec<String> {
    let inodes: std::collections::HashSet<String> = fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| fs::read_link(e.path()).ok())
                .filter_map(|l| {
                    l.to_string_lossy()
                        .strip_prefix("socket:[")?
                        .strip_suffix(']')
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default();
    let mut out = vec![];
    for f in ["tcp", "tcp6"] {
        for l in fs::read_to_string(format!("/proc/{pid}/net/{f}"))
            .unwrap_or_default()
            .lines()
            .skip(1)
        {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.get(3) == Some(&"0A") && c.get(9).is_some_and(|i| inodes.contains(*i)) {
                let port = c[1]
                    .rsplit(':')
                    .next()
                    .and_then(|p| u16::from_str_radix(p, 16).ok())
                    .unwrap_or(0);
                out.push(format!("tcp port {port}"));
            }
        }
    }
    for l in fs::read_to_string(format!("/proc/{pid}/net/unix"))
        .unwrap_or_default()
        .lines()
        .skip(1)
    {
        let c: Vec<&str> = l.split_whitespace().collect();
        let listening = c
            .get(3)
            .and_then(|f| u32::from_str_radix(f, 16).ok())
            .is_some_and(|f| f & 0x10000 != 0);
        if listening && c.get(6).is_some_and(|i| inodes.contains(*i)) {
            out.push(format!("unix socket {}", c.get(7).unwrap_or(&"(unnamed)")));
        }
    }
    out
}
