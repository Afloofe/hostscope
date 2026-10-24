use std::fmt::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {

    Char(char),

    Enter,

    Esc,

    Backspace,

    Up,

    Down,

    PageUp,

    PageDown,

    Home,

    End,

    Tab,

    BackTab,

    F(u8),
}

impl Key {

    pub fn label(self) -> String {
        match self {
            Key::Char(' ') => "Space".into(),
            Key::Char(c) => c.to_string(),
            Key::Enter => "Enter".into(),
            Key::Esc => "Esc".into(),
            Key::Backspace => "Backspace".into(),
            Key::Up => "↑".into(),
            Key::Down => "↓".into(),
            Key::PageUp => "PgUp".into(),
            Key::PageDown => "PgDn".into(),
            Key::Home => "Home".into(),
            Key::End => "End".into(),
            Key::Tab => "Tab".into(),
            Key::BackTab => "Shift-Tab".into(),
            Key::F(n) => format!("F{n}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPat {

    Is(Key),

    Printable,

    Any,
}

impl KeyPat {
    fn matches(self, k: Key) -> bool {
        match self {
            KeyPat::Is(x) => x == k,
            KeyPat::Printable => matches!(k, Key::Char(c) if !c.is_control()),
            KeyPat::Any => true,
        }
    }

    pub fn label(self) -> String {
        match self {
            KeyPat::Is(k) => k.label(),
            KeyPat::Printable => "any printable key".into(),
            KeyPat::Any => "any other key".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mouse {

    Button(&'static str),

    Tab,

    Row,

    WheelUp,

    WheelDown,

    Scrollbar,

    KeyCap,

    Canned,

    Toc,

    Outside,
}

impl Mouse {

    pub fn label(self, key: Option<KeyPat>) -> String {
        match self {
            Mouse::Button(l) => format!("[{}]", button_text(key, l)),
            Mouse::Tab => "click its tab".into(),
            Mouse::Row => "click a row".into(),
            Mouse::WheelUp => "wheel up".into(),
            Mouse::WheelDown => "wheel down".into(),
            Mouse::Scrollbar => "the scrollbar".into(),
            Mouse::KeyCap => "the on-screen keyboard".into(),
            Mouse::Canned => "click a ready-made reason".into(),
            Mouse::Toc => "click a heading in Contents".into(),
            Mouse::Outside => "click anywhere but [Apply]".into(),
        }
    }
}

pub(crate) fn button_text(key: Option<KeyPat>, label: &str) -> String {
    match key {
        Some(KeyPat::Is(k)) => format!("{} {label}", k.label()),
        _ => label.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {

    Quit,

    NextTab,

    PrevTab,

    GoTab(u8),

    Docs,

    Back,

    Up,

    Down,

    ScrollUp,

    ScrollDown,

    PageUp,

    PageDown,

    Top,

    Bottom,

    Select(usize),

    Rescan,

    Fix,

    Inspect,

    Apply,

    Cancel,

    Reprobe,

    Open,

    Ack,

    Investigate,

    Resolve,

    Note,

    Reread,

    ResolveAs(char),

    Type(char),

    Erase,

    ShiftCase,

    Submit,

    CancelEntry,

    Canned(usize),

    Search,

    NextMatch,

    PrevMatch,

    NextSection,

    PrevSection,

    Section(usize),

    Contents,

    Ticket,

    Edit,

    Clear,

    DryRun,

    RunVerb,

    ShowOutput,

    Arm,

    Stop,

    Keep,

    Revert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {

    Global,

    Docs,

    TextEntry,

    Reason,

    Posture,

    Findings,

    Evidence,

    Confirm,

    Alerts,

    Detail,

    Lines,

    ResolveKind,

    VerbList,

    VerbForm,

    VerbValue,

    VerbOutput,

    VerbConfirm,
}

impl Mode {

    pub fn title(self) -> &'static str {
        match self {
            Mode::Global => "Anywhere (not while typing or confirming)",
            Mode::Docs => "Docs tab",
            Mode::TextEntry => "Typing text (search, reason, note)",
            Mode::Reason => "Typing a reason or a note",
            Mode::Posture => "Posture tab",
            Mode::Findings => "Findings tab",
            Mode::Evidence => "Evidence tab",
            Mode::Confirm => "APPLY? confirmation",
            Mode::Alerts => "Alerts tab",
            Mode::Detail => "One alert's detail",
            Mode::Lines => "Hosts and Clusters tabs",
            Mode::ResolveKind => "Choosing a resolution",
            Mode::VerbList => "Verbs tab: the list",
            Mode::VerbForm => "Verbs tab: one verb's flags",
            Mode::VerbValue => "Verbs tab: entering a value (with the typing keys)",
            Mode::VerbOutput => "Verbs tab: a run's output",
            Mode::VerbConfirm => "Verbs tab: the APPLY? question",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Binding {

    pub mode: Mode,

    pub action: Action,

    pub keys: &'static [KeyPat],

    pub mouse: &'static [Mouse],

    pub desc: &'static str,
}

impl Binding {

    pub fn button(&self) -> Option<&'static str> {
        self.mouse.iter().find_map(|m| match m {
            Mouse::Button(l) => Some(*l),
            _ => None,
        })
    }

    pub fn button_text(&self) -> Option<String> {
        self.button().map(|l| button_text(self.keys.first().copied(), l))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Table {

    pub view: &'static str,

    pub groups: &'static [&'static [Binding]],
}

impl Table {

    pub fn all(&self) -> impl Iterator<Item = &'static Binding> + '_ {
        self.groups.iter().flat_map(|g| g.iter())
    }

    pub fn in_mode(&self, mode: Mode) -> impl Iterator<Item = &'static Binding> + '_ {
        self.all().filter(move |b| b.mode == mode)
    }

    pub fn lookup(&self, chain: &[Mode], key: Key) -> Option<Action> {
        for &m in chain {
            for b in self.in_mode(m) {
                if let Some(p) = b.keys.iter().find(|p| p.matches(key)) {
                    return Some(match (p, b.action, key) {
                        (KeyPat::Printable, Action::Type(_), Key::Char(c)) => Action::Type(c),
                        _ => b.action,
                    });
                }
            }
        }
        None
    }

    pub fn permits(&self, chain: &[Mode], a: Action) -> bool {
        chain.iter().any(|&m| {
            self.in_mode(m).any(|b| match a {
                Action::Select(_) => b.mouse.contains(&Mouse::Row),
                Action::Section(_) => b.mouse.contains(&Mouse::Toc),
                Action::Type(_) => matches!(b.action, Action::Type(_)),
                _ => b.action == a,
            })
        })
    }

    pub fn wheel(&self, chain: &[Mode], up: bool) -> Option<Action> {
        let want = if up { Mouse::WheelUp } else { Mouse::WheelDown };
        chain
            .iter()
            .find_map(|&m| self.in_mode(m).find(|b| b.mouse.contains(&want)).map(|b| b.action))
    }

    pub fn buttons(&self, chain: &[Mode]) -> Vec<(String, Action)> {
        let mut out: Vec<(String, Action)> = Vec::new();
        for &m in chain {
            for b in self.in_mode(m) {
                if let Some(t) = b.button_text() {
                    if !out.iter().any(|(_, a)| *a == b.action) {
                        out.push((t, b.action));
                    }
                }
            }
        }
        out
    }

    pub fn controls_markdown(&self) -> String {
        let mut out = format!("## {}\n\n", self.view);
        let mut modes: Vec<Mode> = Vec::new();
        for b in self.all() {
            if !modes.contains(&b.mode) {
                modes.push(b.mode);
            }
        }
        for m in modes {
            let _ = writeln!(out, "### {}\n", m.title());
            for b in self.in_mode(m) {
                let keys: Vec<String> = b.keys.iter().map(|k| k.label()).collect();
                let first = b.keys.first().copied();
                let mouse: Vec<String> = b.mouse.iter().map(|x| x.label(first)).collect();
                let _ = writeln!(out, "- {}: keys {}; mouse {}", b.desc, keys.join(" or "), mouse.join(", "));
            }
            out.push('\n');
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {

    Key(Key),

    Click {

        x: u16,

        y: u16,
    },

    Wheel {

        up: bool,
    },
}
