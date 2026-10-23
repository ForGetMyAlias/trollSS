//! обходы проверки которые не лезут в джаву: фейковый ввод, удалёнка, песочницы, трюки со временем и загрузкой,
//! другие юзеры, замаскированные jar, обёртки лаунчера, ebpf, LD_PRELOAD у других процессов.
use super::mods::walk;
use crate::model::*;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::AtomicU32;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Bypass;

struct Proc {
    pid: u32,
    comm: String,
    cmd: String,
}

fn procs() -> Vec<Proc> {
    let Ok(rd) = fs::read_dir("/proc") else {
        return vec![];
    };
    rd.flatten()
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_str()?.parse().ok()?;
            let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()?
                .trim()
                .to_string();
            let cmd = fs::read(format!("/proc/{pid}/cmdline"))
                .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
                .unwrap_or_default();
            Some(Proc {
                pid,
                comm,
                cmd: cmd.trim().to_string(),
            })
        })
        .collect()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn cmd(bin: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(bin).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

const INPUT_TOOLS: &[(&str, Sev)] = &[
    ("xdotool", Sev::Warn),
    ("ydotool", Sev::Warn),
    ("evemu-device", Sev::Warn),
    ("evemu-event", Sev::Warn),
    ("xte", Sev::Warn),
    ("xmacro", Sev::Warn),
    ("autokey-gtk", Sev::Warn),
    ("autokey-qt", Sev::Warn),
    ("autokey-run", Sev::Warn),
    ("evsieve", Sev::Warn),
    ("interception", Sev::Warn),
    ("kmonad", Sev::Info),
    ("keyd", Sev::Info),
    ("input-remapper", Sev::Info),
    ("input-remapper-", Sev::Info),
    ("sxhkd", Sev::Info),
    ("xbindkeys", Sev::Info),
];
const REMOTE_TOOLS: &[&str] = &[
    "anydesk",
    "teamviewer",
    "TeamViewer",
    "rustdesk",
    "sunshine",
    "moonlight",
    "parsecd",
    "x11vnc",
    "Xvnc",
    "vncserver",
    "wayvnc",
    "krfb",
    "xrdp",
    "gnome-remote-d",
    "chrome-remote-d",
    "nxserver",
    "todesk",
    "ToDesk",
    "sunloginclient",
    "AweSun",
    "rdesktop",
    "xfreerdp",
];
const REMOTE_PORTS: &[u16] = &[
    22, 3389, 5938, 7070, 47984, 47989, 47990, 48010, 21115, 21116, 21117, 21118, 21119,
];

impl Check for Bypass {
    fn name(&self) -> &'static str {
        "Bypass attempts"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("bypass");
        let ps = procs();

        // 1. фейковый ввод
        for p in &ps {
            if let Some((_, sev)) = INPUT_TOOLS
                .iter()
                .find(|(n, _)| p.comm.starts_with(n) && p.comm != "ydotoold")
            {
                o.add(
                    *sev,
                    format!(
                        "input automation/remapping tool running: {} (PID {})",
                        p.comm, p.pid
                    ),
                );
            }
            if let Ok(fds) = fs::read_dir(format!("/proc/{}/fd", p.pid)) {
                if fds.flatten().any(|f| {
                    fs::read_link(f.path()).is_ok_and(|l| l.to_string_lossy() == "/dev/uinput")
                }) {
                    if p.comm == "ydotoold" {
                        continue;
                    }
                    let sev = if p.comm.starts_with("steam")
                        || p.comm == "keyd"
                        || p.comm.starts_with("input-remapper")
                    {
                        Sev::Info
                    } else {
                        Sev::Warn
                    };
                    o.add(
                        sev,
                        format!(
                            "{} (PID {}) holds /dev/uinput open: it can create fake input devices",
                            p.comm, p.pid
                        ),
                    );
                }
            }
        }
        if let Ok(rd) = fs::read_dir("/sys/class/input") {
            let virt: Vec<String> = rd
                .flatten()
                .filter(|e| {
                    fs::canonicalize(e.path())
                        .is_ok_and(|p| p.to_string_lossy().contains("/devices/virtual/input/"))
                })
                .filter_map(|e| fs::read_to_string(e.path().join("name")).ok())
                .map(|s| s.trim().to_string())
                .filter(|n| !n.contains("ydotoold"))
                .collect();
            if !virt.is_empty() {
                o.add(
                    Sev::Info,
                    format!("virtual input devices present: {}", virt.join(", ")),
                );
            }
        }
        set_pct(pct, 1, 9);

        // 2. удалённое управление
        for p in &ps {
            if REMOTE_TOOLS.iter().any(|t| p.comm.starts_with(t)) {
                o.add(
                    Sev::Warn,
                    format!(
                        "remote-control/streaming software running: {} (PID {})",
                        p.comm, p.pid
                    ),
                );
            }
            if p.comm == "sshd" && p.cmd.starts_with("sshd:") && p.cmd.contains('@') {
                o.add(Sev::Warn, format!("active SSH session: {}", p.cmd));
            }
        }
        for f in ["tcp", "tcp6"] {
            for l in fs::read_to_string(format!("/proc/net/{f}"))
                .unwrap_or_default()
                .lines()
                .skip(1)
            {
                let c: Vec<&str> = l.split_whitespace().collect();
                if c.get(3) != Some(&"01") {
                    continue;
                }
                let port = c[1]
                    .rsplit(':')
                    .next()
                    .and_then(|p| u16::from_str_radix(p, 16).ok())
                    .unwrap_or(0);
                if REMOTE_PORTS.contains(&port) || (5900..=5999).contains(&port) {
                    o.add(
                        Sev::Warn,
                        format!("established inbound connection on remote-access port {port}"),
                    );
                }
            }
        }
        set_pct(pct, 2, 9);

        // 3. песочница: игра в других namespace чем сканер
        if let Some(pid) = ctx.pid {
            for ns in ["pid", "mnt", "net", "user"] {
                let (g, me) = (
                    fs::read_link(format!("/proc/{pid}/ns/{ns}")),
                    fs::read_link(format!("/proc/self/ns/{ns}")),
                );
                if let (Ok(g), Ok(me)) = (g, me) {
                    if g != me {
                        o.add(Sev::Warn, format!("the game runs in a different {ns} namespace than the system (container, flatpak, bwrap, firejail or unshare)"));
                    }
                }
            }
        }
        set_pct(pct, 3, 9);

        // 4. время, загрузка, live системы
        let up: f64 = fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse().ok())
            .unwrap_or(1e9);
        if up < 600.0 {
            o.add(
                Sev::Warn,
                format!("system booted only {:.0} minutes ago", up / 60.0),
            );
        }
        let kc = fs::read_to_string("/proc/cmdline").unwrap_or_default();
        if [
            "boot=casper",
            "archisobasedir",
            "rd.live",
            "toram",
            "boot=live",
            "live-media",
        ]
        .iter()
        .any(|k| kc.contains(k))
        {
            o.add(Sev::Warn, "system is booted from a live image");
        }
        if let Some(rtc) = fs::read_to_string("/sys/class/rtc/rtc0/since_epoch")
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
        {
            // часы железа могут идти по местному времени, поэтому разрешаем целые часовые пояса (кратно 15 минутам)
            let d = (rtc - now()).abs();
            let tz = (d + 450) / 900 * 900;
            if (d - tz).abs() > 300 {
                o.add(
                    Sev::Warn,
                    format!(
                        "system clock differs from the hardware clock by {d}s (clock set by hand?)"
                    ),
                );
            }
        }
        if cmd("timedatectl", &["show", "-p", "NTPSynchronized", "--value"])
            .is_some_and(|v| v.trim() == "no")
        {
            o.add(Sev::Info, "clock is not NTP-synchronized");
        }
        if let Some(j) = cmd(
            "journalctl",
            &[
                "-b",
                "--no-pager",
                "-q",
                "-o",
                "short-iso",
                "-g",
                "Time has been changed|time jumped|Clock change|clock.*stepped",
            ],
        ) {
            for l in j.lines().rev().take(3) {
                o.add(Sev::Warn, format!("clock change logged: {l}"));
            }
        }
        let t = now();
        let mut future = 0;
        walk(&ctx.mc, 4, &mut |p| {
            if fs::metadata(p)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                .is_some_and(|d| d.as_secs() as i64 > t + 120)
            {
                future += 1;
            }
        });
        if future > 0 {
            o.add(
                Sev::Warn,
                format!(
                    "{future} file(s) in the game folder have modification times in the future"
                ),
            );
        }
        set_pct(pct, 4, 9);

        // 5. другие юзеры и другие джавы
        let mut others = vec![];
        for l in fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
        {
            let f: Vec<&str> = l.split(':').collect();
            let (Some(name), Some(uid), Some(home), Some(shell)) = (
                f.first(),
                f.get(2).and_then(|u| u.parse::<u32>().ok()),
                f.get(5),
                f.get(6),
            ) else {
                continue;
            };
            if !(1000..60000).contains(&uid)
                || shell.ends_with("nologin")
                || shell.ends_with("false")
                || Path::new(home) == ctx.home
            {
                continue;
            }
            for d in [
                ".minecraft",
                ".local/share/PrismLauncher",
                ".local/share/FreesmLauncher",
                ".local/share/multimc",
                ".lunarclient",
                ".var/app/org.prismlauncher.PrismLauncher",
            ] {
                if Path::new(home).join(d).exists() {
                    others.push(format!("{name}:{d}"));
                }
            }
        }
        if !others.is_empty() {
            o.add(
                Sev::Warn,
                format!(
                    "other user accounts have Minecraft data: {}",
                    others.join(", ")
                ),
            );
        }
        for p in &ps {
            if Some(p.pid) != ctx.pid && (p.comm == "java" || p.comm.starts_with("javaw")) {
                o.add(
                    Sev::Warn,
                    format!(
                        "another Java process is running: PID {} {}",
                        p.pid,
                        p.cmd.chars().take(120).collect::<String>()
                    ),
                );
            }
        }
        set_pct(pct, 5, 9);

        // 6. замаскированные jar: zip с классами под другим расширением или jar в папках с ассетами
        const PLAIN: &[&str] = &[
            "jar", "zip", "mrpack", "apk", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub",
            "whl", "nupkg", "vsix", "xpi", "kra", "ora", "3mf", "cbz", "aar", "war", "gz", "xz",
            "7z", "tar", "disabled",
        ];
        let mut roots: Vec<(std::path::PathBuf, u32)> = vec![
            (ctx.mc.clone(), 6),
            (ctx.home.join("Downloads"), 3),
            (ctx.home.join("Desktop"), 2),
            (ctx.home.join("Загрузки"), 3),
            (ctx.home.clone(), 0),
            ("/tmp".into(), 3),
            ("/dev/shm".into(), 2),
        ];
        roots.dedup();
        let mut scanned = 0usize;
        for (root, depth) in roots {
            walk(&root, depth, &mut |p| {
                scanned += 1;
                if scanned > 40000 {
                    return;
                }
                let ext = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                let sp = p.to_string_lossy();
                let in_assets = [
                    "/resourcepacks/",
                    "/shaderpacks/",
                    "/saves/",
                    "/screenshots/",
                    "/logs/",
                ]
                .iter()
                .any(|d| sp.contains(d));
                if PLAIN.contains(&ext.as_str()) && !(ext == "jar" && in_assets) {
                    if !(ext == "jar" || ext == "zip") || !in_assets {
                        return;
                    }
                }
                let Ok(meta) = fs::metadata(p) else { return };
                if !(4..=300 << 20).contains(&meta.len()) {
                    return;
                }
                let mut magic = [0u8; 4];
                if fs::File::open(p)
                    .and_then(|mut f| f.read_exact(&mut magic))
                    .is_err()
                    || magic != *b"PK\x03\x04"
                {
                    return;
                }
                let Some(mut z) = fs::File::open(p)
                    .ok()
                    .and_then(|f| zip::ZipArchive::new(f).ok())
                else {
                    return;
                };
                let has_class = (0..z.len().min(5000)).any(|i| {
                    z.by_index_raw(i)
                        .is_ok_and(|e| e.name().is_ok_and(|n| n.ends_with(".class")))
                });
                if has_class {
                    let why = if PLAIN.contains(&ext.as_str()) {
                        "inside an asset/log folder"
                    } else {
                        "with a non-archive extension"
                    };
                    o.add(Sev::Warn, format!("Java classes in a ZIP {why}: {sp}"));
                }
            });
        }
        set_pct(pct, 6, 9);

        // 7. обёртки лаунчера и аргументы джавы
        let mut cfgs: Vec<std::path::PathBuf> = vec![ctx.mc.join("launcher_profiles.json")];
        for base in [
            ctx.home.join(".local/share"),
            ctx.home
                .join(".var/app/org.prismlauncher.PrismLauncher/data"),
            ctx.home.join(".config"),
        ] {
            let Ok(rd) = fs::read_dir(&base) else {
                continue;
            };
            for d in rd.flatten() {
                for f in fs::read_dir(d.path().join("instances"))
                    .into_iter()
                    .flatten()
                    .flatten()
                {
                    cfgs.push(f.path().join("instance.cfg"));
                }
                for f in fs::read_dir(d.path()).into_iter().flatten().flatten() {
                    if f.path().extension().is_some_and(|e| e == "cfg") {
                        cfgs.push(f.path());
                    }
                }
            }
        }
        for c in cfgs {
            let Ok(text) = fs::read_to_string(&c) else {
                continue;
            };
            let label = c
                .to_string_lossy()
                .replace(&*ctx.home.to_string_lossy(), "~");
            for l in text.lines() {
                let l = l.trim();
                let (k, v) = l
                    .split_once('=')
                    .map(|(k, v)| (k.trim(), v.trim()))
                    .or_else(|| {
                        l.split_once("\": \"").map(|(k, v)| {
                            (
                                k.trim_matches(|c| c == '"' || c == ' ' || c == ','),
                                v.trim_end_matches([',', '"']),
                            )
                        })
                    })
                    .unwrap_or(("", ""));
                if v.is_empty() {
                    continue;
                }
                if ["WrapperCommand", "PreLaunchCommand", "PostExitCommand"].contains(&k) {
                    o.add(Sev::Warn, format!("{label}: {k} = {v}"));
                }
                if matches!(k, "JvmArgs" | "javaArgs" | "JvmArguments")
                    && [
                        "-javaagent",
                        "-agentpath",
                        "-agentlib",
                        "-Xbootclasspath",
                        "LD_PRELOAD",
                    ]
                    .iter()
                    .any(|a| v.contains(a))
                {
                    o.add(
                        Sev::Crit,
                        format!("{label}: JVM arguments load native/agent code: {v}"),
                    );
                }
                if matches!(k, "JavaPath" | "javaPath")
                    && (["/tmp/", "/dev/shm/"].iter().any(|p| v.starts_with(p)) || v.contains("/."))
                    && !v.contains("/.local/share/")
                    && !v.contains("/.sdkman/")
                    && !v.contains("/.jdks/")
                    && !v.contains("/.minecraft/runtime")
                {
                    o.add(Sev::Warn, format!("{label}: unusual Java runtime path {v}"));
                }
            }
        }
        set_pct(pct, 7, 9);

        // 8. ebpf программы и LD_PRELOAD у других процессов
        let kinds = [
            (2, "kprobe"),
            (5, "tracepoint"),
            (7, "perf_event"),
            (17, "raw_tracepoint"),
            (26, "tracing"),
            (28, "ext"),
            (29, "lsm"),
        ];
        let mut seen = std::collections::HashSet::new();
        for p in &ps {
            if let Ok(fds) = fs::read_dir(format!("/proc/{}/fd", p.pid)) {
                for f in fds.flatten() {
                    if fs::read_link(f.path())
                        .is_ok_and(|l| l.to_string_lossy() == "anon_inode:bpf-prog")
                    {
                        let info = fs::read_to_string(format!(
                            "/proc/{}/fdinfo/{}",
                            p.pid,
                            f.file_name().to_string_lossy()
                        ))
                        .unwrap_or_default();
                        let ty: i32 = info
                            .lines()
                            .find_map(|l| l.strip_prefix("prog_type:")?.trim().parse().ok())
                            .unwrap_or(-1);
                        if let Some((_, name)) = kinds.iter().find(|(n, _)| *n == ty) {
                            if seen.insert((p.comm.clone(), *name)) {
                                o.add(Sev::Warn, format!("{} (PID {}) holds an eBPF {name} program (kernel-level tracing/hooking)", p.comm, p.pid));
                            }
                        }
                    }
                }
            }
            if Some(p.pid) != ctx.pid {
                if let Ok(env) = fs::read(format!("/proc/{}/environ", p.pid)) {
                    if let Some(v) = env
                        .split(|&c| c == 0)
                        .find_map(|kv| kv.strip_prefix(b"LD_PRELOAD="))
                        .filter(|v| !v.is_empty())
                    {
                        // Steam и оверлеи подгружают свои либы, это просто шум
                        let v = String::from_utf8_lossy(v);
                        if !v.contains("libmozsandbox")
                            && !v.contains("gameoverlayrenderer")
                            && !v.contains("libMangoHud")
                            && !v.contains("libgamemode")
                        {
                            o.add(
                                Sev::Warn,
                                format!("{} (PID {}) runs with LD_PRELOAD={v}", p.comm, p.pid),
                            );
                        }
                    }
                }
            }
        }
        o.v
    }
}
