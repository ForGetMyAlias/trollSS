//! следы зачистки: корзина, история shell, отключённая история, чистилки, отключения USB, вычищенный журнал
use crate::model::*;
use std::process::Command;
use std::sync::atomic::AtomicU32;

pub struct Traces;

impl Check for Traces {
    fn name(&self) -> &'static str {
        "Cleanup traces"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("traces");
        let h = &ctx.home;
        let mut trashed: Vec<(String, String)> = vec![];
        if let Ok(rd) = std::fs::read_dir(h.join(".local/share/Trash/info")) {
            for e in rd.flatten() {
                let s = std::fs::read_to_string(e.path()).unwrap_or_default();
                let path = s
                    .lines()
                    .find_map(|l| l.strip_prefix("Path="))
                    .unwrap_or("");
                let date = s
                    .lines()
                    .find_map(|l| l.strip_prefix("DeletionDate="))
                    .unwrap_or("?");
                if [".jar", ".so", ".exe", ".sh"]
                    .iter()
                    .any(|x| path.ends_with(x))
                {
                    trashed.push((date.to_string(), path.to_string()));
                }
            }
        }
        // обновления модов тоже забивают корзину: показываем несколько свежих, остальное одним числом
        trashed.sort_by(|a, b| b.cmp(a));
        for (date, path) in trashed.iter().take(5) {
            o.add(Sev::Warn, format!("trashed {path} at {date}"));
        }
        if trashed.len() > 5 {
            o.add(
                Sev::Info,
                format!("{} older jar/so/exe/sh entries in trash", trashed.len() - 5),
            );
        }
        set_pct(pct, 1, 5);

        for f in [
            ".bash_history",
            ".zsh_history",
            ".local/share/fish/fish_history",
            ".python_history",
        ] {
            let p = h.join(f);
            let Ok(meta) = std::fs::metadata(&p) else {
                continue;
            };
            if meta.len() == 0 && f != ".python_history" {
                o.add(Sev::Warn, format!("{f} exists but is empty"));
            }
            let text = std::fs::read(&p)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            for l in text.lines() {
                let t = l.rsplit(';').next().unwrap_or(l).trim();
                let bad = [
                    "shred ",
                    "srm ",
                    "wipe ",
                    "history -c",
                    "unset HISTFILE",
                    "HISTFILE=/dev/null",
                    "LD_PRELOAD=",
                    "-javaagent",
                    "ptrace",
                    "gdb ",
                    "bleachbit",
                ]
                .iter()
                .any(|k| t.contains(k))
                    || (t.starts_with("rm ")
                        && (t.contains(".minecraft") || t.contains(".jar") || t.contains("/tmp")))
                    || (t.contains("journalctl") && (t.contains("vacuum") || t.contains("rotate")));
                if bad {
                    o.add(
                        Sev::Warn,
                        format!("{f}: {}", t.chars().take(160).collect::<String>()),
                    );
                }
            }
        }
        for rc in [".bashrc", ".zshrc", ".profile", ".bash_profile"] {
            if let Ok(s) = std::fs::read_to_string(h.join(rc)) {
                if s.lines().any(|l| {
                    !l.trim_start().starts_with('#')
                        && (l.contains("HISTFILE=/dev/null")
                            || l.contains("HISTSIZE=0")
                            || l.contains("unset HISTFILE"))
                }) {
                    o.add(Sev::Warn, format!("{rc} disables shell history"));
                }
            }
        }
        set_pct(pct, 3, 5);

        for t in ["/usr/bin/bleachbit", "/usr/bin/stacer"] {
            if std::path::Path::new(t).exists() {
                o.add(Sev::Info, format!("cleaner installed: {t}"));
            }
        }
        if let Ok(out) = Command::new("journalctl")
            .args([
                "--since",
                "2 days ago",
                "--no-pager",
                "-q",
                "-o",
                "short-iso",
            ])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = text.lines().collect();
            if lines.len() < 200 {
                o.add(
                    Sev::Warn,
                    format!(
                        "journal has only {} lines for 2 days (vacuumed, volatile, or not systemd)",
                        lines.len()
                    ),
                );
            }
            for l in lines
                .iter()
                .filter(|l| l.contains("usb") && l.contains("disconnect"))
                .rev()
                .take(10)
            {
                o.add(Sev::Warn, format!("USB disconnect: {l}"));
            }
        }
        o.v
    }
}
