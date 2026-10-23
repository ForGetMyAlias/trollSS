//! смотрим структуру jar в mods/ и во временных папках: агент в манифесте, нативка внутри, обфускация, нет метаданных
use super::classes::{cp_utf8, vocab_findings};
use crate::model::*;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::AtomicU32;

pub struct Mods;

pub fn walk(dir: &Path, depth: u32, f: &mut dyn FnMut(&Path)) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() && depth > 0 => walk(&p, depth - 1, f),
            Ok(t) if t.is_file() => f(&p),
            _ => {}
        }
    }
}

impl Check for Mods {
    fn name(&self) -> &'static str {
        "Mods & jars"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("mods");
        let mut jars = vec![];
        walk(&ctx.mc.join("mods"), 3, &mut |p| {
            if p.extension().is_some_and(|e| e == "jar") {
                jars.push(p.to_path_buf());
            }
        });
        // jar и нативки в местах куда нормальный софт их не кладёт
        let mut strays = vec![];
        for d in ["/tmp", "/dev/shm", "/var/tmp"] {
            walk(Path::new(d), 3, &mut |p| {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "jar" || ext == "so" {
                    strays.push(p.to_path_buf());
                }
            });
        }
        for s in &strays {
            let p = s.to_string_lossy();
            // JNI либы вроде voicechat распаковываются в /tmp/lib<имя>4j-<хеш>/
            let benign = ["/tmp/lwjgl", "/tmp/jna", "/tmp/.org.lwjgl"]
                .iter()
                .any(|b| p.starts_with(b))
                || (p.starts_with("/tmp/lib") && p.contains("4j-"));
            if !benign {
                o.add(Sev::Warn, format!("jar/so in temp dir: {p}"));
            }
        }
        o.add(Sev::Info, format!("{} jars in mods/", jars.len()));
        for (i, j) in jars.iter().enumerate() {
            set_pct(pct, i as u64, jars.len() as u64);
            let name = j.file_name().unwrap().to_string_lossy().into_owned();
            let Ok(mut z) = File::open(j)
                .ok()
                .and_then(|f| zip::ZipArchive::new(f).ok())
                .ok_or(())
            else {
                o.add(Sev::Warn, format!("{name}: not a readable zip"));
                continue;
            };
            let names: Vec<String> = (0..z.len())
                .filter_map(|i| {
                    z.by_index_raw(i)
                        .ok()
                        .and_then(|e| e.name().map(|c| c.into_owned()).ok())
                })
                .collect();
            let has = |s: &str| names.iter().any(|n| n == s);
            if let Ok(mut m) = z.by_name("META-INF/MANIFEST.MF") {
                let mut s = String::new();
                let _ = m.read_to_string(&mut s);
                if s.contains("Premain-Class") || s.contains("Agent-Class") {
                    o.add(Sev::Crit, format!("{name}: manifest declares a Java agent"));
                }
            }
            if !(has("mcmod.info")
                || has("fabric.mod.json")
                || has("quilt.mod.json")
                || has("META-INF/mods.toml")
                || has("META-INF/neoforge.mods.toml")
                || has("pack.mcmeta"))
            {
                o.add(
                    Sev::Warn,
                    format!("{name}: no mod metadata (not a Forge/Fabric/Quilt mod)"),
                );
            }
            let natives: Vec<&String> = names
                .iter()
                .filter(|n| [".so", ".dll", ".dylib"].iter().any(|e| n.ends_with(e)))
                .collect();
            if !natives.is_empty() {
                o.add(
                    Sev::Warn,
                    format!("{name}: embeds native code ({})", natives[0]),
                );
            }
            let classes: Vec<&String> = names.iter().filter(|n| n.ends_with(".class")).collect();
            let short = classes
                .iter()
                .filter(|n| {
                    n.trim_end_matches(".class")
                        .rsplit('/')
                        .next()
                        .is_some_and(|b| b.len() <= 2)
                })
                .count();
            if classes.len() >= 20 && short * 100 / classes.len() >= 40 {
                o.add(
                    Sev::Warn,
                    format!(
                        "{name}: heavy obfuscation ({short}/{} classes with 1–2 char names)",
                        classes.len()
                    ),
                );
            }
            let class_names: Vec<String> = classes
                .iter()
                .map(|n| n.trim_end_matches(".class").to_string())
                .collect();
            vocab_findings(&mut o, class_names.into_iter(), &format!("in {name}"));
            scan_classes(&mut z, &names, &name, &mut o);
            if has("net/java/i.class") && has("l.png") {
                o.add(
                    Sev::Crit,
                    format!("{name}: matches known Doomsday jar layout"),
                );
            }
            if let (Some(start), Ok(Ok(m))) =
                (ctx.started, std::fs::metadata(j).map(|m| m.modified()))
            {
                if m.duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
                    > start
                {
                    o.add(
                        Sev::Warn,
                        format!("{name}: modified after Minecraft started"),
                    );
                }
            }
        }
        o.v
    }
}

const OK_HOSTS: &[&str] = &[
    "modrinth.com",
    "mojang.com",
    "minecraft.net",
    "microsoft.com",
    "github.com",
    "githubusercontent.com",
    "curseforge.com",
    "fabricmc.net",
    "minecraftforge.net",
    "neoforged.net",
    "discord.com",
    "discord.gg",
    "ko-fi.com",
    "patreon.com",
    "w3.org",
    "apache.org",
    "oracle.com",
    "java.com",
    "xml.org",
    "openjdk.org",
    "gnu.org",
    "wikipedia.org",
    "example.com",
    "google.com",
    "eclipse.org",
    "sonatype.org",
    "maven.org",
    "gradle.org",
    "lwjgl.org",
    "spongepowered.org",
    "readthedocs.io",
    "gitlab.com",
    "bsky.app",
    "twitter.com",
    "youtube.com",
    "paypal.com",
    "buymeacoffee.com",
];

/// лезем внутрь классов: что код умеет делать, неважно как классы называются
fn scan_classes<R: std::io::Read + std::io::Seek>(
    z: &mut zip::ZipArchive<R>,
    names: &[String],
    jar: &str,
    o: &mut Out,
) {
    let mut hits: std::collections::BTreeMap<&'static str, String> = Default::default();
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    for n in names.iter().filter(|n| n.ends_with(".class")).take(6000) {
        let Ok(mut e) = z.by_name(n) else { continue };
        if e.size() > 2 << 20 {
            continue;
        }
        let mut buf = Vec::with_capacity(e.size() as usize);
        if e.read_to_end(&mut buf).is_err() || buf.get(..4) != Some(&[0xCA, 0xFE, 0xBA, 0xBE]) {
            continue;
        }
        let u = cp_utf8(&buf);
        let has = |p: &str| u.iter().any(|s| s.starts_with(p.as_bytes()));
        let eq = |p: &str| u.iter().any(|s| *s == p.as_bytes());
        let mut mark = |k: &'static str| {
            hits.entry(k)
                .or_insert_with(|| n.trim_end_matches(".class").to_string());
        };
        if has("java/lang/instrument/") {
            mark("instrumentation API (can rewrite classes at runtime)");
        }
        if has("java/awt/Robot") {
            mark("java.awt.Robot (synthetic mouse/keyboard input)");
        }
        if has("java/lang/ProcessBuilder") || (eq("exec") && has("java/lang/Runtime")) {
            mark("starts external processes");
        }
        if has("com/sun/jna/")
            && u.iter().any(|s| {
                s.windows(11)
                    .any(|w| w.eq_ignore_ascii_case(b"mouse_event"))
                    || s.windows(9).any(|w| w.eq_ignore_ascii_case(b"sendinput"))
            })
        {
            mark("JNA calls into OS input APIs");
        }
        if eq("loadLibrary") || (eq("load") && has("java/lang/System")) {
            mark("loads native libraries");
        }
        if has("sun/misc/Unsafe") || has("jdk/internal/misc/Unsafe") {
            mark("Unsafe memory access");
        }
        for s in &u {
            if let Some(rest) = s
                .strip_prefix(b"https://")
                .or_else(|| s.strip_prefix(b"http://"))
            {
                let host: String = String::from_utf8_lossy(rest)
                    .chars()
                    .take_while(|c| !matches!(c, '/' | ':' | '?' | ' '))
                    .collect::<String>()
                    .to_lowercase();
                if host.contains('.')
                    && !OK_HOSTS
                        .iter()
                        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
                {
                    hosts.insert(host);
                }
            }
        }
    }
    for (k, class) in &hits {
        // запуск процессов/нативки/инструментация в классе с именем "c" или "a" это как раз как выглядят обфусцированные дропперы и загрузчики
        let short = class.rsplit('/').next().is_some_and(|c| {
            c.trim_end_matches(|ch: char| ch == '$' || ch.is_ascii_digit())
                .len()
                <= 2
        });
        let risky = k.starts_with("starts external")
            || k.starts_with("loads native")
            || k.starts_with("instrumentation");
        let sev = if short && risky {
            Sev::Crit
        } else if k.starts_with("instrumentation")
            || k.starts_with("java.awt.Robot")
            || k.starts_with("JNA")
        {
            Sev::Warn
        } else {
            Sev::Info
        };
        o.add(sev, format!("{jar}: {k} (e.g. {class})"));
    }
    if !hosts.is_empty() {
        o.add(
            Sev::Info,
            format!(
                "{jar}: contacts hosts outside the usual set: {}",
                hosts.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
            ),
        );
    }
}
