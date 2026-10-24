use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Vector {

    DeviceNode {

        path: String,

        mode: u32,

        group: Option<String>,
    },

    Tool {

        name: String,

        path: String,

        surface: &'static str,
    },

    Portal {

        detail: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub vectors: Vec<Vector>,
}

impl Report {

    pub fn world_readable_nodes(&self) -> impl Iterator<Item = &Vector> {
        self.vectors.iter().filter(|v| {
            matches!(v, Vector::DeviceNode { mode, .. } if mode & 0o004 != 0)
        })
    }
}

const TOOLS: &[(&str, &str)] = &[
    ("grim", "Wayland (wlroots screencopy)"),
    ("wayshot", "Wayland (wlroots screencopy)"),
    ("spectacle", "KDE (portal or X11)"),
    ("flameshot", "X11 / portal"),
    ("scrot", "X11 (XGetImage)"),
    ("maim", "X11 (XGetImage)"),
    ("import", "X11 (ImageMagick, XGetImage)"),
    ("xwd", "X11 (window dump)"),
    ("gnome-screenshot", "GNOME (portal)"),
    ("ffmpeg", "X11 x11grab / DRM kmsgrab"),
    ("wf-recorder", "Wayland (screencopy, video)"),
];

fn path_dirs() -> Vec<String> {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .filter(|d| !d.is_empty())
        .map(str::to_string)
        .collect()
}

fn group_name(gid: u32) -> Option<String> {
    let text = crate::saferead::read_scan_target(std::path::Path::new("/etc/group"))?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        let this = f.get(2)?.parse::<u32>().ok()?;
        (this == gid).then(|| (*f.first().unwrap_or(&"")).to_string())
    })
}

pub fn report() -> Report {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    let mut vectors = Vec::new();

    let mut nodes = vec!["/dev/fb0".to_string()];
    if let Ok(dir) = fs::read_dir("/dev/dri") {
        for e in dir.flatten() {
            if let Some(p) = e.path().to_str() {
                nodes.push(p.to_string());
            }
        }
    }
    nodes.sort();
    for path in nodes {
        if let Ok(md) = fs::metadata(&path) {
            vectors.push(Vector::DeviceNode {
                path,
                mode: md.permissions().mode() & 0o777,
                group: group_name(md.gid()),
            });
        }
    }

    for (name, surface) in TOOLS {
        for dir in path_dirs() {
            let candidate = format!("{dir}/{name}");
            if Path::new(&candidate).exists() {
                vectors.push(Vector::Tool {
                    name: (*name).to_string(),
                    path: candidate,
                    surface,
                });
                break;
            }
        }
    }

    for (probe, label) in [
        ("/usr/share/dbus-1/services/org.freedesktop.impl.portal.desktop.gnome.service", "xdg-desktop-portal (GNOME)"),
        ("/usr/share/dbus-1/services/org.freedesktop.impl.portal.desktop.kde.service", "xdg-desktop-portal (KDE)"),
        ("/usr/lib/xdg-desktop-portal-wlr", "xdg-desktop-portal-wlr (wlroots)"),
    ] {
        if Path::new(probe).exists() {
            vectors.push(Vector::Portal { detail: label.to_string() });
        }
    }

    Report { vectors }
}
