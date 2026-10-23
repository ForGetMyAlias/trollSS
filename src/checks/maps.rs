//! странности в карте памяти: код без файла, удалённые либы, нативки из левых мест, левая исполняемая память
use crate::model::*;
use std::collections::BTreeSet;
use std::sync::atomic::AtomicU32;

pub struct Maps;

#[derive(PartialEq, Clone, Copy)]
pub enum Trust {
    System,
    Benign,
    Foreign,
    Staging,
}

const SYSTEM: &[&str] = &[
    "/usr/",
    "/lib",
    "/opt/",
    "/app/",
    "/nix/",
    "/snap/",
    "/run/host/",
    "/gnu/store/",
];
const BENIGN_TMP: &[&str] = &[
    "/tmp/lwjgl",
    "/tmp/jna",
    "/tmp/.org.lwjgl",
    "/tmp/sqlite",
    "/tmp/ffi",
    "/tmp/.mount_",
];
/// общая память от графики и звука (pipewire, mesa и тд). по имени пропускаем, чтобы не было шума.
/// исполняемый memfd не из этого списка всё равно критичный, а каждую либу ещё смотрит agent проверка.
const BENIGN_MEMFD: &[&str] = &[
    "/memfd:pipewire",
    "/memfd:/.gl",
    "/memfd:wayland",
    "/memfd:mesa",
    "/memfd:doublemapper",
    "/memfd:xshmfence",
    "/memfd:shm",
];

pub fn benign_memfd(path: &str) -> bool {
    BENIGN_MEMFD.iter().any(|b| path.starts_with(b))
}
const STAGING: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"];
const HIDDEN_OK: &[&str] = &[
    ".minecraft",
    ".local",
    ".cache",
    ".gradle",
    ".sdkman",
    ".steam",
    ".var",
    ".jdks",
    ".config",
    ".lunarclient",
    ".sdkman",
];

pub fn is_so(base: &str) -> bool {
    base.ends_with(".so")
        || base
            .find(".so.")
            .is_some_and(|i| base[i + 4..].starts_with(|c: char| c.is_ascii_digit()))
}

/// папка джавы где лежит libjvm.so, её считаем системной
pub fn jdk_root(regs: &[Region]) -> Option<String> {
    let p = regs.iter().find(|r| r.path.ends_with("/libjvm.so"))?;
    let mut d = std::path::Path::new(&p.path).parent()?;
    for _ in 0..2 {
        d = d.parent()?;
    }
    Some(d.to_string_lossy().into_owned())
}

pub fn trust(path: &str, ctx: &Ctx, jdk: &Option<String>) -> Trust {
    let p = path.trim_end_matches(" (deleted)");
    if BENIGN_TMP.iter().any(|b| p.starts_with(b))
        || (p.starts_with("/tmp/lib") && p.contains("4j-"))
        || p.contains("/.cache/JNA/")
    {
        return Trust::Benign;
    }
    if STAGING.iter().any(|s| p.starts_with(s)) {
        return Trust::Staging;
    }
    if SYSTEM.iter().any(|s| p.starts_with(s)) || jdk.as_deref().is_some_and(|j| p.starts_with(j)) {
        return Trust::System;
    }
    if p.starts_with(ctx.mc.to_string_lossy().as_ref()) {
        return Trust::Benign;
    }
    let home = ctx.home.to_string_lossy();
    let rel = p.strip_prefix(home.as_ref()).unwrap_or(p);
    if rel
        .split('/')
        .any(|c| c.starts_with('.') && c.len() > 1 && !HIDDEN_OK.contains(&c))
    {
        return Trust::Staging;
    }
    Trust::Foreign
}

/// либы которые подгружены в процесс и не из системы, по одному региону на либу
pub fn nonsystem_libs<'a>(ctx: &Ctx, regs: &'a [Region]) -> Vec<(&'a Region, Trust)> {
    let jdk = jdk_root(regs);
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    for r in regs {
        let base = r.path.rsplit('/').next().unwrap_or("");
        if !(is_so(base.trim_end_matches(" (deleted)")) || r.path.starts_with("/memfd:"))
            || benign_memfd(&r.path)
            || !seen.insert(&r.path)
        {
            continue;
        }
        let t = if r.path.starts_with("/memfd:") {
            Trust::Staging
        } else {
            trust(&r.path, ctx, &jdk)
        };
        if t != Trust::System {
            out.push((r, t));
        }
    }
    out
}

impl Check for Maps {
    fn name(&self) -> &'static str {
        "Memory maps"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("maps");
        if ctx.pid.is_none() {
            o.add(Sev::Info, "no Minecraft process — skipped");
            return o.v;
        }
        let regs = ctx.maps();
        if regs.is_empty() {
            o.add(Sev::Warn, "cannot read /proc/PID/maps");
            return o.v;
        }
        for (i, r) in regs.iter().enumerate() {
            set_pct(pct, i as u64, regs.len() as u64 * 2);
            if r.path.starts_with("/memfd:") {
                if !benign_memfd(&r.path) {
                    let sev = if r.x() { Sev::Crit } else { Sev::Warn };
                    o.add(
                        sev,
                        format!(
                            "fileless mapping {} [{}] at {:x}",
                            r.path,
                            String::from_utf8_lossy(&r.perms),
                            r.start
                        ),
                    );
                }
            } else if r.path.ends_with("(deleted)")
                && (r.x()
                    || is_so(
                        r.path
                            .trim_end_matches(" (deleted)")
                            .rsplit('/')
                            .next()
                            .unwrap_or(""),
                    )
                    || r.path.contains(".jar"))
            {
                // JNA/LWJGL/libffi сами удаляют свои временные либы после загрузки, всё остальное похоже на заметание следов
                if !BENIGN_TMP.iter().any(|b| r.path.starts_with(b))
                    && !r.path.contains("/.cache/JNA/")
                {
                    o.add(
                        Sev::Crit,
                        format!(
                            "deleted-but-mapped {} [{}]",
                            r.path,
                            String::from_utf8_lossy(&r.perms)
                        ),
                    );
                }
            }
        }
        for (r, t) in nonsystem_libs(ctx, &regs) {
            match t {
                // моды нормально распаковывают нативки в /tmp, а вот удалить файл сразу после загрузки это уже палево
                Trust::Staging if r.path.ends_with("(deleted)") => o.add(
                    Sev::Crit,
                    format!(
                        "native lib loaded from a staging path and deleted: {}",
                        r.path
                    ),
                ),
                Trust::Staging => o.add(
                    Sev::Warn,
                    format!("native lib from staging/hidden path: {}", r.path),
                ),
                Trust::Foreign => o.add(
                    Sev::Warn,
                    format!("native lib outside system/JDK/.minecraft: {}", r.path),
                ),
                _ => {}
            }
        }
        // исполняемую анонимную память смотрит jvm проверка, она знает где реально лежит JIT кэш
        o.v
    }
}

/// анонимная исполняемая память которая не JIT. если знаем точные границы кэша от джавы, то всё точно;
/// если не знаем, то кэшем считаем самый большой кусок подряд или тот за которым идёт закрытая зона.
pub fn anon_exec_suspects(regs: &[Region], jit: Option<&[(u64, u64)]>) -> Vec<(Sev, String)> {
    let mut clusters: Vec<(u64, u64, u64, bool)> = vec![];
    for r in regs
        .iter()
        .filter(|r| r.x() && r.anon() && r.path != "[vdso]")
    {
        match clusters.last_mut() {
            Some(c) if c.1 == r.start => {
                c.1 = r.end;
                c.2 += r.size();
                c.3 |= r.w();
            }
            _ => clusters.push((r.start, r.end, r.size(), r.w())),
        }
    }
    let biggest = clusters.iter().map(|c| c.2).max().unwrap_or(0);
    let reserved = |start: u64, end: u64| {
        regs.iter().any(|r| {
            &r.perms == b"---p"
                && r.anon()
                && r.size() >= 1 << 20
                && (r.start == end || r.end == start)
        })
    };
    let mut out = vec![];
    for c in &clusters {
        let benign = match jit {
            Some(j) => j.iter().any(|&(lo, hi)| c.0 >= lo && c.1 <= hi),
            None => c.2 == biggest || reserved(c.0, c.1),
        };
        if benign {
            continue;
        }
        let sev = if c.2 >= 1 << 20 || (c.3 && c.2 >= 64 << 10) {
            Sev::Crit
        } else if c.2 >= 4096 {
            Sev::Warn
        } else {
            continue;
        };
        out.push((
            sev,
            format!(
                "anon executable region {:x}-{:x} ({} KiB{}) outside the JIT code cache",
                c.0,
                c.1,
                c.2 / 1024,
                if c.3 { ", writable" } else { "" }
            ),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn so_names() {
        assert!(is_so("libc.so.6"));
        assert!(is_so("libfoo.so"));
        assert!(!is_so("ld.so.cache"));
    }
}
