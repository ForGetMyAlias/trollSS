use image::{DynamicImage, RgbaImage};
use ratatui::DefaultTerminal;
use ratatui::layout::{Alignment, Constraint, Flex, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Gauge, Paragraph};
use ratatui_image::{
    StatefulImage,
    picker::{Picker, ProtocolType},
};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
use std::time::{Duration, Instant};

const TROLL: &[u8] = include_bytes!("../assets/troll.png");

pub fn run(
    term: &mut DefaultTerminal,
    pcts: &[AtomicU32],
    done: &[AtomicBool],
) -> std::io::Result<()> {
    let t0 = Instant::now();
    // надо вызывать уже после входа в альтернативный экран. если терминал не умеет картинки, рисуем блоками
    let mut picker = Picker::from_query_stdio().unwrap_or_else(|_| Picker::halfblocks());
    // sudo вырезает переменные терминала и ломает запрос возможностей, поэтому смотрим на родительские процессы пользователя
    if picker.protocol_type() == ProtocolType::Halfblocks && speaks_kitty() {
        picker.set_protocol_type(ProtocolType::Kitty);
    }
    let img = cutout(image::load_from_memory(TROLL).map_err(std::io::Error::other)?);
    // подгоняем область картинки под её пропорции, чтобы она ровно стояла над текстом и полосой
    let fs = picker.font_size();
    let (fw, fh) = (fs.width, fs.height);
    let rows: u16 = 16;
    let cols = ((rows as f32 * fh as f32 * img.width() as f32 / img.height() as f32)
        / fw.max(1) as f32)
        .round() as u16;
    let mut troll = picker.new_resize_protocol(img);
    loop {
        let all_done = done.iter().all(|d| d.load(Relaxed));
        let total = if all_done {
            100
        } else {
            (pcts.iter().map(|p| p.load(Relaxed) as u64).sum::<u64>() / pcts.len() as u64).min(99)
        };
        let dots = ".".repeat((t0.elapsed().as_millis() / 300 % 4) as usize);
        term.draw(|f| {
            let [col] = Layout::horizontal([Constraint::Length(cols.max(20))])
                .flex(Flex::Center)
                .areas(f.area());
            let [art, text, bar] = Layout::vertical([
                Constraint::Length(rows),
                Constraint::Length(2),
                Constraint::Length(1),
            ])
            .flex(Flex::Center)
            .areas(col);
            f.render_stateful_widget(StatefulImage::default(), art, &mut troll);
            f.render_widget(
                Paragraph::new(format!("\nSCANNING{dots:<3} {total}%"))
                    .alignment(Alignment::Center)
                    .style(Style::new().add_modifier(Modifier::BOLD)),
                text,
            );
            f.render_widget(
                Gauge::default()
                    .percent(total as u16)
                    .label("")
                    .gauge_style(Style::new().fg(Color::White).bg(Color::DarkGray)),
                bar,
            );
        })?;
        if all_done {
            std::thread::sleep(Duration::from_millis(500));
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// увеличиваем картинку и делаем белый фон (который касается края) прозрачным, белая заливка лица остаётся
fn cutout(img: DynamicImage) -> DynamicImage {
    let big = img.resize(
        img.width() * 4,
        img.height() * 4,
        image::imageops::FilterType::Lanczos3,
    );
    let mut px: RgbaImage = big.to_rgba8();
    let (w, h) = px.dimensions();
    let bg = |p: &image::Rgba<u8>| p[3] < 10 || (p[0] > 225 && p[1] > 225 && p[2] > 225);
    let mut seen = vec![false; (w * h) as usize];
    let mut stack: Vec<(u32, u32)> = (0..w)
        .flat_map(|x| [(x, 0), (x, h - 1)])
        .chain((0..h).flat_map(|y| [(0, y), (w - 1, y)]))
        .collect();
    while let Some((x, y)) = stack.pop() {
        let i = (y * w + x) as usize;
        if seen[i] || !bg(px.get_pixel(x, y)) {
            continue;
        }
        seen[i] = true;
        px.get_pixel_mut(x, y)[3] = 0;
        if x > 0 {
            stack.push((x - 1, y));
        }
        if y > 0 {
            stack.push((x, y - 1));
        }
        if x + 1 < w {
            stack.push((x + 1, y));
        }
        if y + 1 < h {
            stack.push((x, y + 1));
        }
    }
    DynamicImage::ImageRgba8(px)
}

/// проверяем: этот процесс или кто-то из родителей запущен в терминале который умеет kitty graphics
fn speaks_kitty() -> bool {
    let hit = |env: &[u8]| {
        env.split(|&c| c == 0).any(|kv| {
            let kv = String::from_utf8_lossy(kv);
            kv.starts_with("GHOSTTY_")
                || kv.starts_with("KITTY_WINDOW_ID=")
                || kv == "TERM_PROGRAM=ghostty"
                || kv == "TERM=xterm-kitty"
                || kv == "TERM=xterm-ghostty"
        })
    };
    let mut pid = std::process::id();
    for _ in 0..10 {
        if std::fs::read(format!("/proc/{pid}/environ")).is_ok_and(|e| hit(&e)) {
            return true;
        }
        let ppid = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| {
                s.rsplit_once(')')?
                    .1
                    .split_whitespace()
                    .nth(1)?
                    .parse::<u32>()
                    .ok()
            });
        match ppid {
            Some(p) if p > 1 => pid = p,
            _ => break,
        }
    }
    false
}
