mod checks;
mod model;
mod ui;

use model::*;
use std::io::IsTerminal;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};

/// ищем java процесс который похож на майн, берём тот что жрёт больше памяти
fn find_minecraft() -> Option<u32> {
    let mut best: Option<(u64, u32)> = None;
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let cmd = std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| String::from_utf8_lossy(&b).to_lowercase())
            .unwrap_or_default();
        let exe = cmd.split('\0').next().unwrap_or("");
        if !(exe.ends_with("java") || exe.ends_with("javaw"))
            || !(cmd.contains("minecraft")
                || cmd.contains("net.fabricmc")
                || cmd.contains("cpw.mods")
                || cmd.contains("lunar"))
        {
            continue;
        }
        let rss = std::fs::read_to_string(format!("/proc/{pid}/statm"))
            .ok()
            .and_then(|s| s.split_whitespace().nth(1)?.parse().ok())
            .unwrap_or(0);
        if best.is_none_or(|b| rss > b.0) {
            best = Some((rss, pid));
        }
    }
    best.map(|b| b.1)
}

fn home_of(uid: u32) -> Option<PathBuf> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.get(2)?.parse::<u32>().ok()? == uid).then(|| PathBuf::from(f[5]))
        })
}

fn build_ctx() -> Ctx {
    let pid = find_minecraft();
    let uid = pid
        .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/status")).ok())
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Uid:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u32>()
                    .ok()
            })
        })
        .or_else(|| std::env::var("SUDO_UID").ok()?.parse().ok())
        .unwrap_or(unsafe { libc::getuid() });
    let home = home_of(uid)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or("/root".into())));
    let game_dir = pid.and_then(|p| {
        let a: Vec<String> = std::fs::read(format!("/proc/{p}/cmdline"))
            .ok()?
            .split(|&c| c == 0)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        a.iter()
            .position(|x| x == "--gameDir")
            .and_then(|i| a.get(i + 1))
            .map(PathBuf::from)
    });
    let started = pid
        .and_then(|p| {
            std::fs::metadata(format!("/proc/{p}"))
                .ok()?
                .modified()
                .ok()?
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
        })
        .map(|d| d.as_secs());
    // лаунчеры (Prism, Freesm, MultiMC) запускают игру из папки minecraft внутри инстанса
    let cwd = pid
        .and_then(|p| std::fs::read_link(format!("/proc/{p}/cwd")).ok())
        .filter(|c| {
            c.join("mods").is_dir() || c.join("logs").is_dir() || c.join("options.txt").exists()
        });
    Ctx {
        pid,
        mc: game_dir.or(cwd).unwrap_or_else(|| home.join(".minecraft")),
        home,
        root: unsafe { libc::geteuid() } == 0,
        started,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!(
            "trollss [--no-ui] [--json FILE]\nRun as root while Minecraft is running. Read-only; nothing is executed or modified."
        );
        return;
    }
    let json_path = args
        .iter()
        .position(|a| a == "--json")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "trollss-report.json".into());
    let use_ui = std::io::stdout().is_terminal() && !args.iter().any(|a| a == "--no-ui");

    let ctx = build_ctx();
    let checks = checks::all();
    let pcts: Vec<AtomicU32> = checks.iter().map(|_| AtomicU32::new(0)).collect();
    let done: Vec<AtomicBool> = checks.iter().map(|_| AtomicBool::new(false)).collect();
    let found: Mutex<Vec<Finding>> = Mutex::new(vec![]);
    let mut header = vec![
        format!(
            "PID  : {}",
            ctx.pid.map_or("not running".into(), |p| p.to_string())
        ),
        format!("MC   : {}", ctx.mc.display()),
        format!("root : {}", ctx.root),
    ];
    if !ctx.root {
        header.push("! not root: memory checks will be partial".into());
    }

    std::thread::scope(|s| {
        for (i, c) in checks.iter().enumerate() {
            let (ctx, pcts, done, found) = (&ctx, &pcts, &done, &found);
            s.spawn(move || {
                let r = catch_unwind(AssertUnwindSafe(|| c.run(ctx, &pcts[i])));
                let v = r.unwrap_or_else(|_| {
                    vec![Finding {
                        check: "runner",
                        sev: Sev::Warn,
                        msg: format!("check '{}' crashed", c.name()),
                    }]
                });
                found.lock().unwrap().extend(v);
                pcts[i].store(100, Relaxed);
                done[i].store(true, Relaxed);
            });
        }
        if use_ui {
            let mut term = ratatui::init();
            let _ = ui::run(&mut term, &pcts, &done);
            ratatui::restore();
        } else {
            while !done.iter().all(|d| d.load(Relaxed)) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    });

    let mut f = found.into_inner().unwrap();
    f.sort_by(|a, b| b.sev.cmp(&a.sev).then(a.check.cmp(b.check)));
    let (crit, warn) = (
        f.iter().filter(|x| x.sev == Sev::Crit).count(),
        f.iter().filter(|x| x.sev == Sev::Warn).count(),
    );
    // с интерфейсом ничего не печатаем, всё идёт только в json. без интерфейса (--no-ui или пайп) печатаем
    if !use_ui {
        for l in &header {
            println!("{l}");
        }
        for x in &f {
            let tag = match x.sev {
                Sev::Crit => "[!!]",
                Sev::Warn => "[! ]",
                Sev::Info => "[i ]",
            };
            println!("{tag} {:<10} {}", x.check, x.msg);
        }
        println!(
            "\n{crit} critical, {warn} warnings. No findings is NOT proof of a clean system (see README limits)."
        );
    }
    if serde_json::to_string_pretty(&f)
        .map(|j| std::fs::write(&json_path, j))
        .is_err()
    {
        eprintln!("could not write {json_path}");
    }
    std::process::exit(if crit > 0 {
        2
    } else if warn > 0 {
        1
    } else {
        0
    });
}
