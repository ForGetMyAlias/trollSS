use serde::Serialize;
use std::fs::{self, File};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicU32;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Debug)]
pub enum Sev {
    Info,
    Warn,
    Crit,
}

#[derive(Clone, Serialize)]
pub struct Finding {
    pub check: &'static str,
    pub sev: Sev,
    pub msg: String,
}

/// сюда проверка складывает свои находки
pub struct Out {
    check: &'static str,
    pub v: Vec<Finding>,
}

impl Out {
    pub fn new(check: &'static str) -> Self {
        Out {
            check,
            v: Vec::new(),
        }
    }
    pub fn add(&mut self, sev: Sev, msg: impl Into<String>) {
        self.v.push(Finding {
            check: self.check,
            sev,
            msg: msg.into(),
        });
    }
}

pub struct Ctx {
    pub pid: Option<u32>,
    pub mc: PathBuf,
    pub home: PathBuf,
    pub root: bool,
    /// когда процесс стартанул (в секундах, берём из /proc/PID)
    pub started: Option<u64>,
}

pub struct Region {
    pub start: u64,
    pub end: u64,
    pub perms: [u8; 4],
    pub offset: u64,
    pub path: String,
}

impl Region {
    pub fn r(&self) -> bool {
        self.perms[0] == b'r'
    }
    pub fn w(&self) -> bool {
        self.perms[1] == b'w'
    }
    pub fn x(&self) -> bool {
        self.perms[2] == b'x'
    }
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
    pub fn anon(&self) -> bool {
        self.path.is_empty() || self.path.starts_with("[anon")
    }
}

impl Ctx {
    pub fn maps(&self) -> Vec<Region> {
        let Some(pid) = self.pid else { return vec![] };
        let Ok(s) = fs::read_to_string(format!("/proc/{pid}/maps")) else {
            return vec![];
        };
        s.lines().filter_map(parse_map_line).collect()
    }

    pub fn mem(&self) -> Option<File> {
        File::open(format!("/proc/{}/mem", self.pid?)).ok()
    }

    pub fn cmdline(&self) -> Vec<String> {
        nul_split(&format!("/proc/{}/cmdline", self.pid.unwrap_or(0)))
    }

    pub fn environ(&self) -> Vec<String> {
        nul_split(&format!("/proc/{}/environ", self.pid.unwrap_or(0)))
    }

    /// весь файл за маппингом, читается даже если удалён или memfd (нужен root)
    pub fn mapped_file(&self, r: &Region) -> Option<Vec<u8>> {
        let f = File::open(format!(
            "/proc/{}/map_files/{:x}-{:x}",
            self.pid?, r.start, r.end
        ))
        .ok()?;
        if f.metadata().ok()?.len() > 256 << 20 {
            return None;
        }
        let mut buf = vec![0; f.metadata().ok()?.len() as usize];
        f.read_exact_at(&mut buf, 0).ok()?;
        Some(buf)
    }
}

fn nul_split(path: &str) -> Vec<String> {
    fs::read(path)
        .map(|b| {
            b.split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_map_line(line: &str) -> Option<Region> {
    let mut it = line.splitn(6, ' ');
    let (a, b) = it.next()?.split_once('-')?;
    let p = it.next()?.as_bytes();
    let offset = u64::from_str_radix(it.next()?, 16).ok()?;
    it.next()?;
    it.next()?;
    Some(Region {
        start: u64::from_str_radix(a, 16).ok()?,
        end: u64::from_str_radix(b, 16).ok()?,
        perms: [*p.first()?, *p.get(1)?, *p.get(2)?, *p.get(3)?],
        offset,
        path: it.next().unwrap_or("").trim().to_string(),
    })
}

pub trait Check: Sync {
    fn name(&self) -> &'static str;
    /// процент должен дойти до 100 только когда всё реально сделано, остальное ставит раннер
    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding>;
}

pub fn set_pct(pct: &AtomicU32, done: u64, total: u64) {
    let p = if total == 0 {
        100
    } else {
        (done * 100 / total).min(99)
    };
    pct.store(p as u32, std::sync::atomic::Ordering::Relaxed);
}
