//! ищем впрыснутые классы без сигнатур: достаём классы из памяти джавы и сверяем имена со всеми jar которые игра может грузить
use super::mods::walk;
use crate::model::*;
use memchr::memmem;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Cursor, Read};
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicU32;

pub struct Classes;

const CHUNK: usize = 8 << 20;
const OVERLAP: usize = 128 << 10;
/// пакеты которые лежат в самой джаве (не в jar) или создаются на ходу
const IGNORE_PREFIX: &[&str] = &[
    "java/",
    "javax/",
    "jdk/",
    "sun/",
    "com/sun/",
    "org/w3c/",
    "org/xml/",
    "org/ietf/",
    "org/omg/",
    "org/spongepowered/asm/synthetic/",
    "com/llamalad7/mixinextras/sugar/impl/ref/generated/",
    // Forge на ходу переименовывает классы, поэтому имена из памяти никогда не совпадут с jar
    "net/minecraft",
    "net/minecraftforge/",
    "cpw/mods/",
];
const IGNORE_CONTAINS: &[&str] = &[
    "$$",
    "$Proxy",
    "/0x",
    "Generated",
    "$Lambda",
    "/generated/",
    "$FieldGetter",
    "$FieldSetter",
];

impl Check for Classes {
    fn name(&self) -> &'static str {
        "Injected classes"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("classes");
        let Some(mem) = ctx.mem() else {
            o.add(Sev::Info, "no process memory access — skipped");
            return o.v;
        };
        let (known, trusted_jars) = known(ctx);
        let regs: Vec<Region> = ctx
            .maps()
            .into_iter()
            .filter(|r| {
                r.r()
                    && r.w()
                    && (r.anon()
                        || r.path == "[heap]"
                        || r.path.starts_with("/memfd:")
                        || r.path.ends_with("(deleted)"))
            })
            .collect();
        let total: u64 = regs.iter().map(|r| r.size()).sum();
        let finder = memmem::Finder::new(&[0xCA, 0xFE, 0xBA, 0xBE]);
        let mut seen: HashSet<String> = HashSet::new();
        let (mut done, mut buf) = (0u64, vec![0u8; CHUNK + OVERLAP]);
        for r in &regs {
            let mut pos = r.start;
            while pos < r.end {
                let want = ((r.end - pos) as usize).min(CHUNK + OVERLAP);
                let n = match mem.read_at(&mut buf[..want], pos) {
                    Ok(n) if n > 0 => n,
                    _ => break,
                };
                for off in finder.find_iter(&buf[..n]) {
                    if let Some(name) = class_name(&buf[off..n]) {
                        seen.insert(name);
                    }
                }
                // кусок до конца региона надо брать целиком, иначе хвост читается по одному байту
                let step = if r.end - pos <= (CHUNK + OVERLAP) as u64 {
                    want
                } else {
                    CHUNK
                };
                pos += step as u64;
                done += step as u64;
                set_pct(pct, done, total);
            }
        }

        let startup_mods = startup_mod_ids(ctx);
        for j in open_jars(ctx) {
            let clean = j.trim_end_matches(" (deleted)");
            hot_added(ctx, clean, startup_mods.as_ref(), &mut o);
            if trusted_jars.contains(std::path::Path::new(clean)) {
                continue;
            }
            let staged = j.ends_with("(deleted)")
                || ["/tmp/", "/dev/shm/", "/var/tmp/", "/memfd:"]
                    .iter()
                    .any(|p| clean.starts_with(p));
            let jdk =
                clean.starts_with("/usr/") || clean.starts_with("/opt/") || clean.contains("/jvm/");
            if staged {
                o.add(Sev::Crit, format!("JVM has a jar open that was not on the launch classpath, from a staging path or deleted: {j}"));
            } else if !jdk {
                o.add(Sev::Warn, format!("JVM has a jar open that is not on the launch classpath or in the game directory: {j}"));
            }
        }
        let _ = judge(&mut o, &seen, known, "in memory");
        o.v
    }
}

/// показывает имена классов которых нет ни в одном jar. src это откуда взяли имена
pub fn judge(
    o: &mut Out,
    seen: &HashSet<String>,
    known: &HashSet<String>,
    src: &str,
) -> Vec<String> {
    let mut unknown: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in seen {
        if known.contains(n)
            || IGNORE_PREFIX.iter().any(|p| n.starts_with(p))
            || IGNORE_CONTAINS.iter().any(|c| n.contains(c))
        {
            continue;
        }
        let pkg = n.rsplit_once('/').map_or("", |x| x.0).to_string();
        unknown.entry(pkg).or_default().push(n.clone());
    }
    o.add(
        Sev::Info,
        format!(
            "{} distinct classes {src}, {} jars indexed, {} unknown",
            seen.len(),
            known.len(),
            unknown.values().map(Vec::len).sum::<usize>()
        ),
    );
    for (pkg, names) in &unknown {
        // нормальные моды и либы никогда не лежат в дефолтном пакете
        let sev = if names.len() >= 3 || pkg.is_empty() {
            Sev::Crit
        } else {
            Sev::Warn
        };
        let mut s = names.clone();
        s.sort();
        o.add(
            sev,
            format!(
                "class(es) {src} not present in any jar: package '{pkg}' x{} e.g. {}",
                names.len(),
                s[..s.len().min(3)].join(", ")
            ),
        );
    }
    unknown.into_values().flatten().collect()
}

/// имена из самой джавы и те что генерятся на ходу, в jar их нет
pub fn runtime_class(n: &str) -> bool {
    IGNORE_PREFIX.iter().any(|p| n.starts_with(p)) || IGNORE_CONTAINS.iter().any(|c| n.contains(c))
}

/// все имена классов из jar до которых игра может дотянуться: папка майна, рабочая папка процесса и папки используемых jar
pub fn known(ctx: &Ctx) -> &'static (HashSet<String>, HashSet<std::path::PathBuf>) {
    static K: std::sync::OnceLock<(HashSet<String>, HashSet<std::path::PathBuf>)> =
        std::sync::OnceLock::new();
    K.get_or_init(|| known_classes(ctx))
}

fn known_classes(ctx: &Ctx) -> (HashSet<String>, HashSet<std::path::PathBuf>) {
    let mut jars: HashSet<std::path::PathBuf> = HashSet::new();
    let mut roots = vec![ctx.mc.clone()];
    if let Some(pid) = ctx.pid {
        if let Ok(c) = std::fs::read_link(format!("/proc/{pid}/cwd")) {
            roots.push(c);
        }
        // доверяем только classpath с которым запустили. jar которые джава открыла сверх него ищем отдельно
        let mut used: Vec<String> = vec![];
        let args = ctx.cmdline();
        for (i, a) in args.iter().enumerate() {
            if a == "-cp" || a == "-classpath" || a.starts_with("-Djava.class.path=") {
                let v = if a.starts_with("-D") {
                    a.split_once('=').map(|x| x.1.to_string())
                } else {
                    args.get(i + 1).cloned()
                };
                used.extend(v.unwrap_or_default().split(':').map(String::from));
            }
        }
        for u in used.into_iter().filter(|u| u.ends_with(".jar")) {
            if let Some(d) = std::path::Path::new(&u).parent() {
                roots.push(d.to_path_buf());
            }
            jars.insert(u.into());
        }
    }
    for r in roots {
        walk(&r, 8, &mut |p| {
            if p.extension().is_some_and(|e| e == "jar") {
                jars.insert(p.to_path_buf());
            }
        });
    }
    let mut names = HashSet::new();
    for j in &jars {
        if let Ok(f) = File::open(j) {
            index_zip(f, &mut names, 1);
        }
    }
    (names, jars)
}

/// jar которые джава сейчас держит открытыми или замапленными
fn open_jars(ctx: &Ctx) -> HashSet<String> {
    let mut v: HashSet<String> = ctx.maps().into_iter().map(|r| r.path).collect();
    if let Some(pid) = ctx.pid {
        if let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
            v.extend(
                rd.flatten()
                    .filter_map(|e| std::fs::read_link(e.path()).ok())
                    .map(|p| p.to_string_lossy().into_owned()),
            );
        }
    }
    v.into_iter()
        .filter(|p| p.trim_end_matches(" (deleted)").ends_with(".jar"))
        .collect()
}

fn index_zip<R: Read + std::io::Seek>(r: R, out: &mut HashSet<String>, depth: u8) {
    let Ok(mut z) = zip::ZipArchive::new(r) else {
        return;
    };
    let mut nested = vec![];
    for i in 0..z.len() {
        let Ok(e) = z.by_index_raw(i) else { continue };
        let n = e.name().map(|c| c.into_owned()).unwrap_or_default();
        let n = n.as_str();
        if let Some(c) = n.strip_suffix(".class") {
            out.insert(c.to_string());
        } else if depth > 0
            && n.ends_with(".jar")
            && (n.starts_with("META-INF/jars/")
                || n.starts_with("META-INF/jarjar/")
                || n.starts_with("META-INF/libraries/"))
        {
            nested.push(i);
        }
    }
    for i in nested {
        let Ok(mut e) = z.by_index(i) else { continue };
        if e.size() > 64 << 20 {
            continue;
        }
        let mut b = Vec::with_capacity(e.size() as usize);
        if e.read_to_end(&mut b).is_ok() {
            index_zip(Cursor::new(b), out, depth - 1);
        }
    }
}

/// разбираем заголовок класса ровно настолько чтобы достать this_class. b начинается с магии 0xCAFEBABE
fn class_name(b: &[u8]) -> Option<String> {
    let u2 = |o: usize| {
        b.get(o..o + 2)
            .map(|x| u16::from_be_bytes([x[0], x[1]]) as usize)
    };
    let major = u2(6)?;
    if !(45..=80).contains(&major) {
        return None;
    }
    let count = u2(8)?;
    if count < 2 {
        return None;
    }
    let mut utf8: Vec<Option<(usize, usize)>> = vec![None; count];
    let mut class_name_idx = vec![0usize; count];
    let (mut off, mut i) = (10, 1);
    while i < count {
        let tag = *b.get(off)?;
        off += 1;
        match tag {
            1 => {
                let len = u2(off)?;
                utf8[i] = Some((off + 2, len));
                off += 2 + len;
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => off += 4,
            5 | 6 => {
                off += 8;
                i += 1;
            }
            7 => {
                class_name_idx[i] = u2(off)?;
                off += 2;
            }
            8 | 16 | 19 | 20 => off += 2,
            15 => off += 3,
            _ => return None,
        }
        i += 1;
    }
    let this_class = u2(off + 2)?;
    let (s, l) = utf8
        .get(*class_name_idx.get(this_class)?)?
        .as_ref()
        .copied()?;
    let raw = b.get(s..s + l)?;
    if l == 0
        || l > 200
        || !raw
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_$/-".contains(c))
    {
        return None;
    }
    Some(String::from_utf8_lossy(raw).into_owned())
}

/// сильные слова: названия модулей которые почти только в читах. слабые слова обычные и считаются только числом
const STRONG: &[&str] = &[
    "killaura",
    "aimassist",
    "aimbot",
    "autoclicker",
    "triggerbot",
    "scaffold",
    "bhop",
    "bunnyhop",
    "antikb",
    "antiknockback",
    "noslowdown",
    "nofall",
    "autototem",
    "crystalaura",
    "cevbreak",
];
const WEAK: &[&str] = &[
    "reach",
    "velocity",
    "criticals",
    "hitbox",
    "esp",
    "xray",
    "fullbright",
    "flight",
    "speedhack",
    "timer",
    "sprint",
    "nuker",
    "blink",
    "tracers",
    "chams",
];

/// возвращает (сильное, слабое) совпадение для имени класса типа a/b/KillAura$1
pub fn cheat_words(class: &str) -> (Option<&'static str>, Option<&'static str>) {
    let simple = class.rsplit('/').next().unwrap_or("");
    // режем по словам: "KillAura$1" -> kill, aura. слабые слова только целым словом ("ESP", "Reach"), не кусок от "Response"
    let mut words: Vec<String> = vec![];
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in simple.chars() {
        if !c.is_alphanumeric() || (c.is_uppercase() && prev_lower) {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur).to_lowercase());
            }
        }
        if c.is_alphanumeric() {
            cur.push(c);
        }
        prev_lower = c.is_lowercase();
    }
    if !cur.is_empty() {
        words.push(cur.to_lowercase());
    }
    let joined = words.concat();
    (
        STRONG.iter().copied().find(|w| joined.contains(w)),
        WEAK.iter().copied().find(|w| words.iter().any(|x| x == w)),
    )
}

/// группируем по пакету: одно сильное слово это предупреждение, два сильных (или сильное + 2 слабых) критично, слабые сами по себе ничего не дают
pub fn vocab_findings(o: &mut Out, names: impl Iterator<Item = String>, src: &str) {
    let mut by_pkg: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    for n in names {
        let (s, w) = cheat_words(&n);
        let pkg = n.rsplit_once('/').map_or("", |x| x.0).to_string();
        if s.is_some() {
            by_pkg.entry(pkg).or_default().0.push(n);
        } else if w.is_some() {
            by_pkg.entry(pkg).or_default().1.push(n);
        }
    }
    for (pkg, (strong, weak)) in by_pkg {
        let (ns, nw) = (strong.len(), weak.len());
        let sev = if ns >= 2 || (ns >= 1 && nw >= 2) {
            Sev::Crit
        } else if ns >= 1 {
            Sev::Warn
        } else {
            continue;
        };
        let sample: Vec<String> = strong
            .iter()
            .chain(&weak)
            .take(4)
            .map(|n| n.rsplit('/').next().unwrap_or(n).to_string())
            .collect();
        o.add(sev, format!("cheat-module vocabulary {src}: package '{pkg}' has {ns} strong + {nw} weak class names ({})", sample.join(", ")));
    }
}

/// все Utf8 константы класса (ссылки на классы, имена, строки). b начинается с магии
pub fn cp_utf8(b: &[u8]) -> Vec<&[u8]> {
    let u2 = |o: usize| {
        b.get(o..o + 2)
            .map(|x| u16::from_be_bytes([x[0], x[1]]) as usize)
    };
    let (Some(count), mut off, mut i, mut out) = (u2(8), 10usize, 1usize, vec![]) else {
        return vec![];
    };
    while i < count {
        let Some(&tag) = b.get(off) else { break };
        off += 1;
        match tag {
            1 => {
                let Some(len) = u2(off) else { break };
                if let Some(s) = b.get(off + 2..off + 2 + len) {
                    out.push(s);
                }
                off += 2 + len;
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => off += 4,
            5 | 6 => {
                off += 8;
                i += 1;
            }
            7 | 8 | 16 | 19 | 20 => off += 2,
            15 => off += 3,
            _ => break,
        }
        i += 1;
    }
    out
}

/// id модов которые Fabric записал при старте ("Loading N mods:" и потом строки "- id версия", вложенные как "\-- id")
fn startup_mod_ids(ctx: &Ctx) -> Option<HashSet<String>> {
    let log = std::fs::read_to_string(ctx.mc.join("logs/latest.log")).ok()?;
    let mut ids = HashSet::new();
    let mut in_list = false;
    for l in log.lines() {
        if l.contains("Loading ") && l.contains(" mods:") {
            in_list = true;
            continue;
        }
        if in_list {
            if l.starts_with('[') || l.trim().is_empty() {
                in_list = false;
                continue;
            }
            let t = l.trim_start();
            if let Some(rest) = t.strip_prefix("- ").or_else(|| t.strip_prefix("\\-- ")) {
                if let Some(id) = rest.split_whitespace().next() {
                    ids.insert(id.to_string());
                }
            }
        }
    }
    (!ids.is_empty()).then_some(ids)
}

/// мод добавили в уже запущенную игру (как DFabric): jar новее процесса или его id не было в списке при старте
fn hot_added(ctx: &Ctx, path: &str, startup: Option<&HashSet<String>>, o: &mut Out) {
    use std::os::unix::fs::MetadataExt;
    let p = std::path::Path::new(path);
    let Ok(meta) = std::fs::metadata(p) else {
        return;
    };
    // Fabric сам пересобирает моды в .fabric/ после старта процесса, их ловит проверка по id
    if let Some(start) = ctx.started {
        if !path.contains("/.fabric/") && meta.ctime() > start as i64 + 5 {
            o.add(Sev::Crit, format!("jar open in the JVM was created/changed after Minecraft started (mod added at runtime): {path}"));
        }
    }
    let Some(startup) = startup else { return };
    let Some(mut z) = File::open(p)
        .ok()
        .and_then(|f| zip::ZipArchive::new(f).ok())
    else {
        return;
    };
    let Ok(mut e) = z.by_name("fabric.mod.json") else {
        return;
    };
    let mut buf = Vec::new();
    if e.read_to_end(&mut buf).is_err() {
        return;
    }
    if let Some(id) = serde_json::from_slice::<serde_json::Value>(&buf)
        .ok()
        .and_then(|v| v.get("id")?.as_str().map(String::from))
    {
        if !startup.contains(&id) {
            o.add(Sev::Crit, format!("mod '{id}' is loaded but was not in the startup mod list (hot-added after launch): {path}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_name_from_minimal_class_file() {
        let mut b = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 3];
        b.extend([1, 0, 7]);
        b.extend(b"Foo/Bar");
        b.extend([7, 0, 1]);
        b.extend([0, 0x21, 0, 2]);
        assert_eq!(class_name(&b).as_deref(), Some("Foo/Bar"));
        assert_eq!(class_name(&b[..12]), None);
    }

    #[test]
    fn cheat_words_match_whole_words_only() {
        assert!(cheat_words("a/b/KillAura$1").0.is_some());
        assert_eq!(cheat_words("a/b/ErrorResponse"), (None, None));
        assert_eq!(cheat_words("a/b/ESP").1, Some("esp"));
        assert_eq!(
            cheat_words("com/velocitypowered/VelocityCompressor").0,
            None
        );
    }
}
