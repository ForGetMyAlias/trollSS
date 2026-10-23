//! штуки которые прячут читы от проверок на хосте: виртуалка, контейнер, Wine, VPN
use crate::model::*;
use std::fs;
use std::sync::atomic::AtomicU32;

pub struct SysEnv;

fn read(p: &str) -> String {
    fs::read_to_string(p).unwrap_or_default().trim().to_string()
}

impl Check for SysEnv {
    fn name(&self) -> &'static str {
        "VM / container / VPN"
    }

    fn run(&self, ctx: &Ctx, pct: &AtomicU32) -> Vec<Finding> {
        let mut o = Out::new("sysenv");
        if fs::read_to_string("/proc/cpuinfo")
            .unwrap_or_default()
            .lines()
            .any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "hypervisor"))
        {
            o.add(
                Sev::Warn,
                "CPU reports a hypervisor: running inside a virtual machine",
            );
        }
        let dmi = format!(
            "{} {}",
            read("/sys/class/dmi/id/sys_vendor"),
            read("/sys/class/dmi/id/product_name")
        )
        .to_lowercase();
        if [
            "vmware",
            "virtualbox",
            "innotek",
            "qemu",
            "kvm",
            "bochs",
            "parallels",
            "xen",
            "standard pc",
        ]
        .iter()
        .any(|k| dmi.contains(k))
        {
            o.add(
                Sev::Warn,
                format!("DMI identifies a virtual machine: {dmi}"),
            );
        }
        let mods = read("/proc/modules");
        if mods.lines().any(|l| {
            ["vboxguest", "vmw_", "virtio_pci", "hv_vmbus"]
                .iter()
                .any(|m| l.starts_with(m))
        }) {
            o.add(
                Sev::Warn,
                "guest kernel modules loaded (vbox/vmware/virtio/hyperv)",
            );
        }
        set_pct(pct, 1, 3);

        let cg = read("/proc/1/cgroup");
        if std::path::Path::new("/.dockerenv").exists()
            || std::path::Path::new("/run/.containerenv").exists()
            || ["docker", "containerd", "lxc", "kubepods"]
                .iter()
                .any(|k| cg.contains(k))
        {
            o.add(Sev::Crit, "running inside a container");
        }
        let init = read("/proc/1/comm");
        if !matches!(
            init.as_str(),
            "systemd" | "init" | "runit" | "s6-svscan" | "dinit" | "openrc-init"
        ) {
            o.add(Sev::Warn, format!("unusual PID 1: {init}"));
        }
        if std::path::Path::new("/var/run/docker.sock").exists() {
            o.add(Sev::Info, "docker socket present");
        }

        if ctx.home.join(".wine/drive_c").exists() {
            o.add(
                Sev::Warn,
                "Wine prefix present (~/.wine): Windows cheats can run here",
            );
        }
        if let Ok(rd) = fs::read_dir("/proc") {
            for e in rd.flatten() {
                let c = read(&format!("/proc/{}/comm", e.file_name().to_string_lossy()));
                if c.starts_with("wineserver") || c.ends_with(".exe") {
                    o.add(
                        Sev::Warn,
                        format!(
                            "Wine process running: {c} (PID {})",
                            e.file_name().to_string_lossy()
                        ),
                    );
                }
            }
        }
        set_pct(pct, 2, 3);

        hotspot(&mut o);
        if let Ok(rd) = fs::read_dir("/sys/class/net") {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                let ty = read(&format!("/sys/class/net/{n}/type"));
                let tun = ty == "65534"
                    || [
                        "tun",
                        "tap",
                        "wg",
                        "ppp",
                        "nordlynx",
                        "proton",
                        "mullvad",
                        "tailscale",
                        "zt",
                    ]
                    .iter()
                    .any(|p| n.starts_with(p));
                if tun
                    && fs::read_to_string(format!("/sys/class/net/{n}/operstate"))
                        .map(|s| s.trim() != "down")
                        .unwrap_or(true)
                {
                    o.add(Sev::Warn, format!("VPN/tunnel interface up: {n}"));
                }
            }
        }
        o.v
    }
}

fn cmd(bin: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(bin).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// точка доступа wifi или модем: другое устройство может сидеть на этом интернете
fn hotspot(o: &mut Out) {
    // софт для точки доступа
    if let Ok(rd) = fs::read_dir("/proc") {
        for e in rd.flatten() {
            let pid = e.file_name().to_string_lossy().into_owned();
            if !pid.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let comm = read(&format!("/proc/{pid}/comm"));
            let cl = fs::read(format!("/proc/{pid}/cmdline"))
                .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
                .unwrap_or_default();
            if matches!(
                comm.as_str(),
                "hostapd" | "create_ap" | "lnxrouter" | "wihotspot" | "linux-wifi-hotspot"
            ) {
                o.add(
                    Sev::Crit,
                    format!("hotspot software running: {comm} (PID {pid})"),
                );
            } else if comm == "dnsmasq"
                && (cl.contains("dhcp-range")
                    || cl.contains("nm-dnsmasq")
                    || cl.contains("/run/NetworkManager/dnsmasq"))
            {
                o.add(
                    Sev::Crit,
                    format!("DHCP server for shared connection running: {}", cl.trim()),
                );
            }
        }
    }
    // интерфейс в режиме точки доступа и кто к нему подключён
    if let Some(iw) = cmd("iw", &["dev"]) {
        let mut ifname = String::new();
        for l in iw.lines().map(str::trim) {
            if let Some(n) = l.strip_prefix("Interface ") {
                ifname = n.to_string();
            }
            if l.starts_with("type AP") || l.starts_with("type P2P-GO") {
                o.add(
                    Sev::Crit,
                    format!("Wi-Fi interface {ifname} is in access-point mode"),
                );
                if let Some(st) = cmd("iw", &["dev", &ifname, "station", "dump"]) {
                    let n = st.lines().filter(|l| l.starts_with("Station ")).count();
                    if n > 0 {
                        o.add(
                            Sev::Crit,
                            format!("{n} device(s) connected to the access point on {ifname}"),
                        );
                    }
                }
            }
        }
    }
    // NetworkManager: активные подключения которые раздают интернет
    if let Some(act) = cmd(
        "nmcli",
        &["-t", "-f", "NAME", "connection", "show", "--active"],
    ) {
        for name in act.lines().filter(|n| !n.is_empty()) {
            if let Some(v) = cmd(
                "nmcli",
                &[
                    "-g",
                    "802-11-wireless.mode,ipv4.method",
                    "connection",
                    "show",
                    name,
                ],
            ) {
                let mut it = v.lines();
                let (mode, method) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
                if mode == "ap" || method == "shared" {
                    o.add(Sev::Crit, format!("NetworkManager connection '{name}' is sharing internet (mode={mode}, ipv4={method})"));
                }
            }
        }
    }
    // выданные dhcp адреса значит устройства были подключены сейчас или недавно
    if let Ok(rd) = fs::read_dir("/var/lib/NetworkManager") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("dnsmasq-") && n.ends_with(".leases") {
                let clients = fs::read_to_string(e.path())
                    .unwrap_or_default()
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .count();
                if clients > 0 {
                    o.add(
                        Sev::Warn,
                        format!("{clients} DHCP lease(s) given to other devices ({n})"),
                    );
                }
            }
        }
    }
    // модем по USB и Bluetooth
    if let Ok(rd) = fs::read_dir("/sys/class/net") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            let drv = fs::read_link(format!("/sys/class/net/{n}/device/driver"))
                .ok()
                .and_then(|p| p.file_name().map(|x| x.to_string_lossy().into_owned()))
                .unwrap_or_default();
            if n.starts_with("bnep")
                || ["rndis_host", "cdc_ether", "cdc_ncm", "ipheth"].contains(&drv.as_str())
            {
                o.add(
                    Sev::Warn,
                    format!(
                        "tethering interface {n} ({})",
                        if drv.is_empty() {
                            "bluetooth PAN"
                        } else {
                            &drv
                        }
                    ),
                );
            }
        }
    }
    if read("/proc/sys/net/ipv4/ip_forward") == "1" {
        o.add(
            Sev::Info,
            "IPv4 forwarding is on (machine routes traffic for others)",
        );
    }
}
