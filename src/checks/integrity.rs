//! сверяем исполняемые страницы либ в памяти с файлом на диске: так видно хуки и патчи
use crate::model::*;
use object::{Object, ObjectSegment, ObjectSymbol};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicU32;

pub struct Integrity;

impl Check for Integrity {
    fn name(&self) -> &'static str {
        "Code integrity"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("integrity");
        let Some(mem) = ctx.mem() else {
            o.add(Sev::Info, "no process memory access — skipped");
            return o.v;
        };
        let regs: Vec<Region> = ctx
            .maps()
            .into_iter()
            .filter(|r| {
                r.r()
                    && r.x()
                    && !r.w()
                    && r.path.starts_with('/')
                    && !r.path.starts_with("/memfd:")
                    && !r.path.starts_with("/dev/")
                    && !r.path.ends_with("(deleted)")
            })
            .collect();
        let total: u64 = regs.iter().map(|r| r.size()).sum();
        let mut done = 0;
        for r in &regs {
            let Ok(disk) = File::open(&r.path) else {
                continue;
            };
            let (mut a, mut b) = (vec![0u8; r.size() as usize], vec![0u8; r.size() as usize]);
            if mem.read_exact_at(&mut a, r.start).is_err()
                || disk.read_exact_at(&mut b, r.offset).is_err()
            {
                continue;
            }
            done += r.size();
            set_pct(pct, done, total);
            let runs = diff_runs(&a, &b);
            let differing: usize = runs.iter().map(|x| x.1 - x.0).sum();
            if runs.is_empty() {
                continue;
            }
            if differing * 100 > a.len() {
                o.add(
                    Sev::Info,
                    format!(
                        "{} differs from disk in {} bytes (library likely updated after launch)",
                        r.path, differing
                    ),
                );
                continue;
            }
            let symbols = std::fs::read(&r.path).ok();
            for &(s, e) in runs.iter().take(8) {
                let jump = matches!(a[s], 0xE9 | 0xE8)
                    || a[s..e.min(s + 2)] == [0xFF, 0x25]
                    || a[s..e.min(s + 2)] == [0x48, 0xB8]
                    || a[s..e.min(s + 2)] == [0x49, 0xBB];
                let sev = if jump { Sev::Crit } else { Sev::Warn };
                let sym = symbols
                    .as_deref()
                    .and_then(|d| symbol_at(d, r.offset + s as u64))
                    .unwrap_or_else(|| "?".into());
                o.add(
                    sev,
                    format!(
                        "{} patched in memory at +{:x} ({} bytes, first {:02x}) in {sym}",
                        r.path,
                        r.offset + s as u64,
                        e - s,
                        a[s]
                    ),
                );
            }
        }
        o.v
    }
}

/// диапазоны где куски не совпали, дырки до 8 одинаковых байт склеиваем
fn diff_runs(a: &[u8], b: &[u8]) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = vec![];
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        if x == y {
            continue;
        }
        match runs.last_mut() {
            Some(l) if i - l.1 <= 8 => l.1 = i + 1,
            _ => runs.push((i, i + 1)),
        }
    }
    runs
}

fn symbol_at(data: &[u8], file_off: u64) -> Option<String> {
    let f = object::File::parse(data).ok()?;
    let seg = f
        .segments()
        .find(|s| s.file_range().0 <= file_off && file_off < s.file_range().0 + s.file_range().1)?;
    let vaddr = seg.address() + (file_off - seg.file_range().0);
    f.symbols()
        .chain(f.dynamic_symbols())
        .find(|s| s.size() > 0 && s.address() <= vaddr && vaddr < s.address() + s.size())
        .and_then(|s| s.name().ok().map(String::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_runs_merges_close_gaps() {
        let a = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut b = a;
        b[1] = 0;
        b[3] = 0;
        assert_eq!(diff_runs(&a, &b), vec![(1, 4)]);
        assert!(diff_runs(&a, &a).is_empty());
    }
}
