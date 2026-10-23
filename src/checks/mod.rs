use crate::model::Check;

mod agent;
mod bypass;
mod classes;
mod integrity;
mod jvm;
mod launch;
mod maps;
mod mods;
mod sysenv;
mod traces;
mod tracing;

/// список проверок: новая проверка = новый файл + одна строка тут
pub fn all() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(launch::Launch),
        Box::new(maps::Maps),
        Box::new(agent::Agent),
        Box::new(integrity::Integrity),
        Box::new(classes::Classes),
        Box::new(jvm::Jvm),
        Box::new(tracing::Tracing),
        Box::new(mods::Mods),
        Box::new(traces::Traces),
        Box::new(sysenv::SysEnv),
        Box::new(bypass::Bypass),
    ]
}
