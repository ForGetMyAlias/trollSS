//! как запустили джаву: preload, странный classpath, флаги против attach
use crate::model::*;
use std::sync::atomic::AtomicU32;

pub struct Launch;

impl Check for Launch {
    fn name(&self) -> &'static str {
        "Launch environment"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("launch");
        if let Ok(s) = std::fs::read_to_string("/etc/ld.so.preload") {
            if !s.trim().is_empty() {
                o.add(
                    Sev::Crit,
                    format!("/etc/ld.so.preload is set: {}", s.trim()),
                );
            }
        }
        if ctx.pid.is_none() {
            o.add(Sev::Info, "no Minecraft process — runtime checks skipped");
            return o.v;
        }
        for e in ctx.environ() {
            let Some((k, v)) = e.split_once('=') else {
                continue;
            };
            match k {
                "LD_PRELOAD" | "LD_AUDIT" => o.add(Sev::Crit, format!("{k}={v}")),
                "LD_LIBRARY_PATH" | "CLASSPATH" | "JAVA_HOME" | "JAVA_TOOL_OPTIONS"
                | "_JAVA_OPTIONS" | "JDK_JAVA_OPTIONS"
                    if !v.is_empty() =>
                {
                    o.add(Sev::Info, format!("{k}={v}"))
                }
                _ => {}
            }
        }
        set_pct(pct, 1, 2);
        for a in ctx.cmdline() {
            // кто прячется от сканеров через attach или ослабляет джаву, уже сам по себе палится
            if a == "-XX:+DisableAttachMechanism"
                || a == "-XX:+AllowUserSignalHandlers"
                || a.starts_with("-Djava.security.manager")
            {
                o.add(Sev::Warn, format!("JVM flag: {a}"));
            }
            if ["/tmp/", "/dev/shm/", "/var/tmp/"]
                .iter()
                .any(|s| a.contains(s))
                && !a.starts_with("-Djava.io.tmpdir")
                && !a.contains("/tmp/lwjgl")
            {
                o.add(
                    Sev::Warn,
                    format!("launch argument points into a temp dir: {a}"),
                );
            }
        }
        if ctx.pid.is_some()
            && std::path::Path::new(&format!("/tmp/.java_pid{}", ctx.pid.unwrap())).exists()
        {
            o.add(
                Sev::Warn,
                "attach socket /tmp/.java_pid<PID> exists: a tool is (or was) attached",
            );
        }
        o.v
    }
}
