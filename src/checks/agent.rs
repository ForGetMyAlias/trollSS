//! ищем агентов в джаве: флаги запуска, подключение на лету, jvmti в нативных либах
use super::maps::{Trust, nonsystem_libs};
use crate::model::*;
use object::{Object, ObjectSymbol};
use std::sync::atomic::AtomicU32;

pub struct Agent;

const AGENT_EXPORTS: &[&str] = &[
    "Agent_OnLoad",
    "Agent_OnAttach",
    "Agent_OnUnload",
    "JVM_OnLoad",
];

impl Check for Agent {
    fn name(&self) -> &'static str {
        "JVM agents"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("agent");
        if ctx.pid.is_none() {
            o.add(Sev::Info, "no Minecraft process — skipped");
            return o.v;
        }
        let mut flags: Vec<String> = ctx
            .cmdline()
            .into_iter()
            .filter(|a| {
                a.starts_with("-javaagent")
                    || a.starts_with("-agentpath")
                    || a.starts_with("-agentlib")
                    || a.starts_with("-Xbootclasspath")
            })
            .collect();
        for e in ctx.environ() {
            if let Some((k, v)) = e.split_once('=') {
                if matches!(
                    k,
                    "JAVA_TOOL_OPTIONS" | "_JAVA_OPTIONS" | "JDK_JAVA_OPTIONS"
                ) && v.contains("-agent")
                {
                    flags.push(format!("{k}={v}"));
                }
            }
        }
        let mut static_agent = false;
        for f in &flags {
            let staged = ["/tmp/", "/dev/shm/", "/var/tmp/"]
                .iter()
                .any(|s| f.contains(s));
            let sev = if staged || f.starts_with("-agentpath") {
                Sev::Crit
            } else if f.contains("jdwp") {
                Sev::Warn
            } else {
                Sev::Info
            };
            static_agent |= f.contains("-javaagent") || f.contains("-agent");
            o.add(sev, format!("JVM flag: {f}"));
        }

        let regs = ctx.maps();
        let mapped = |name: &str| {
            regs.iter().any(|r| {
                r.path
                    .rsplit('/')
                    .next()
                    .is_some_and(|b| b.starts_with(name))
            })
        };
        if mapped("libinstrument") && !static_agent {
            o.add(Sev::Crit, "libinstrument.so loaded but no -javaagent flag: an agent was attached to the running JVM");
        }
        if mapped("libjdwp") || mapped("libdt_socket") {
            o.add(Sev::Warn, "debugger library (jdwp) loaded");
        }

        let libs = nonsystem_libs(ctx, &regs);
        for (i, (r, t)) in libs.iter().enumerate() {
            set_pct(pct, i as u64, libs.len() as u64);
            let Some(data) = ctx.mapped_file(r) else {
                if !ctx.root {
                    o.add(Sev::Info, format!("cannot read {} (need root)", r.path));
                }
                continue;
            };
            let rust = memchr::memmem::find(&data, b"/rustc/").is_some();
            let deleted = r.path.ends_with("(deleted)");
            let Ok(file) = object::File::parse(&*data) else {
                continue;
            };
            let (mut vm_lookup, mut dlopen, mut unlink, mut jni_onload) =
                (false, false, false, false);
            for s in file.dynamic_symbols() {
                let Ok(name) = s.name() else { continue };
                if s.is_definition() && AGENT_EXPORTS.contains(&name) {
                    o.add(
                        Sev::Crit,
                        format!("{} exports {name}: JVMTI agent library", r.path),
                    );
                }
                if s.is_definition() && name == "JNI_OnLoad" {
                    jni_onload = true;
                }
                if s.is_undefined() {
                    match name {
                        "JNI_GetCreatedJavaVMs" => vm_lookup = true,
                        "dlopen" => dlopen = true,
                        "unlink" | "unlinkat" | "remove" => unlink = true,
                        _ => {}
                    }
                }
            }
            if *t == Trust::System {
                continue;
            }
            if vm_lookup {
                // нативка сама находит запущенную джаву, а не грузится через System.loadLibrary
                let hard = rust || deleted || *t == Trust::Staging || !jni_onload;
                o.add(
                    if hard { Sev::Crit } else { Sev::Warn },
                    format!(
                        "{} looks up running JVMs (JNI_GetCreatedJavaVMs){}{}",
                        r.path,
                        if rust { ", Rust-built" } else { "" },
                        if jni_onload {
                            ""
                        } else {
                            ", no JNI_OnLoad (not a normal JNI library)"
                        }
                    ),
                );
            } else if rust {
                o.add(
                    Sev::Warn,
                    format!(
                        "{} is a Rust-built native library loaded into the JVM",
                        r.path
                    ),
                );
            }
            if vm_lookup && dlopen && unlink {
                o.add(
                    Sev::Crit,
                    format!(
                        "{}: loader pattern (finds JVM + dlopen + can delete files)",
                        r.path
                    ),
                );
            }
        }
        o.v
    }
}
