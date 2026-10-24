use crate::input::{Action as A, Binding, Key, KeyPat, Mode as M, Mouse as Ms, Table};

const fn ch(c: char) -> KeyPat {
    KeyPat::Is(Key::Char(c))
}
const fn is(k: Key) -> KeyPat {
    KeyPat::Is(k)
}

const fn b(mode: M, action: A, keys: &'static [KeyPat], mouse: &'static [Ms], desc: &'static str) -> Binding {
    Binding { mode, action, keys, mouse, desc }
}

pub(crate) const DOCS: &[Binding] = &[
    b(M::Docs, A::ScrollUp, &[is(Key::Up), ch('k')], &[Ms::WheelUp, Ms::Scrollbar], "scroll up a line"),
    b(M::Docs, A::ScrollDown, &[is(Key::Down), ch('j')], &[Ms::WheelDown, Ms::Scrollbar], "scroll down a line"),
    b(M::Docs, A::PageUp, &[is(Key::PageUp), ch('b')], &[Ms::Scrollbar], "up a page"),
    b(M::Docs, A::PageDown, &[is(Key::PageDown), ch(' ')], &[Ms::Scrollbar], "down a page"),
    b(M::Docs, A::Top, &[is(Key::Home), ch('g')], &[Ms::Button("Top")], "to the top"),
    b(M::Docs, A::Bottom, &[is(Key::End), ch('G')], &[Ms::Button("Bottom")], "to the end"),
    b(M::Docs, A::Search, &[ch('/')], &[Ms::Button("Find")], "search the docs"),
    b(M::Docs, A::NextMatch, &[ch('n')], &[Ms::Button("Next")], "the next match"),
    b(M::Docs, A::PrevMatch, &[ch('N')], &[Ms::Button("Prev")], "the previous match"),
    b(M::Docs, A::NextSection, &[ch(']')], &[Ms::Toc], "the next section"),
    b(M::Docs, A::PrevSection, &[ch('[')], &[Ms::Toc], "the previous section"),
    b(M::Docs, A::Contents, &[ch('t')], &[Ms::Button("Contents")], "show or hide Contents"),
    b(M::Docs, A::Back, &[is(Key::Esc)], &[Ms::Button("Back")], "back to the tab you came from"),
];

pub(crate) const TEXT: &[Binding] = &[
    b(M::TextEntry, A::Submit, &[is(Key::Enter)], &[Ms::Button("Submit")], "done: search, or record the text"),
    b(M::TextEntry, A::CancelEntry, &[is(Key::Esc)], &[Ms::Button("Cancel")], "give up; nothing is recorded"),
    b(M::TextEntry, A::Erase, &[is(Key::Backspace)], &[Ms::KeyCap], "delete the last character"),
    b(M::TextEntry, A::ShiftCase, &[is(Key::Tab)], &[Ms::KeyCap], "switch the on-screen keyboard's case"),
    b(M::TextEntry, A::Type(' '), &[KeyPat::Printable], &[Ms::KeyCap], "type a character"),
];

pub(crate) const REASON: &[Binding] = &[
    b(M::Reason, A::Canned(0), &[is(Key::F(2))], &[Ms::Canned], "fill in ready-made reason 1"),
    b(M::Reason, A::Canned(1), &[is(Key::F(3))], &[Ms::Canned], "fill in ready-made reason 2"),
    b(M::Reason, A::Canned(2), &[is(Key::F(4))], &[Ms::Canned], "fill in ready-made reason 3"),
    b(M::Reason, A::Canned(3), &[is(Key::F(5))], &[Ms::Canned], "fill in ready-made reason 4"),
    b(M::Reason, A::Canned(4), &[is(Key::F(6))], &[Ms::Canned], "fill in ready-made reason 5"),
    b(M::Reason, A::Canned(5), &[is(Key::F(7))], &[Ms::Canned], "fill in ready-made reason 6"),
];

pub(crate) const CANNED_SLOTS: usize = 6;

const VERB_LIST: &[Binding] = &[
    b(M::VerbList, A::Up, &[is(Key::Up), ch('k')], &[Ms::Button("Up"), Ms::WheelUp, Ms::Row, Ms::Scrollbar], "select the verb above"),
    b(M::VerbList, A::Down, &[is(Key::Down), ch('j')], &[Ms::Button("Down"), Ms::WheelDown, Ms::Row, Ms::Scrollbar], "select the verb below"),
    b(M::VerbList, A::PageUp, &[is(Key::PageUp)], &[Ms::Scrollbar], "ten verbs up"),
    b(M::VerbList, A::PageDown, &[is(Key::PageDown)], &[Ms::Scrollbar], "ten verbs down"),
    b(M::VerbList, A::Open, &[is(Key::Enter)], &[Ms::Button("Open"), Ms::Row], "open the selected verb's flags (or click it again)"),
    b(M::VerbList, A::Ticket, &[ch('t')], &[Ms::Button("Ticket")], "choose the ticket a run presents as $HEMOSTAT_TICKET"),
];
const VERB_FORM: &[Binding] = &[
    b(M::VerbForm, A::Up, &[is(Key::Up), ch('k')], &[Ms::Button("Up"), Ms::Row], "select the field above"),
    b(M::VerbForm, A::Down, &[is(Key::Down), ch('j')], &[Ms::Button("Down"), Ms::Row], "select the field below"),
    b(M::VerbForm, A::Edit, &[is(Key::Enter), ch('e')], &[Ms::Button("Edit"), Ms::Row], "set the selected field: a switch toggles, a value opens its choices (or click it again)"),
    b(M::VerbForm, A::Clear, &[ch('x')], &[Ms::Button("Clear")], "unset the selected field"),
    b(M::VerbForm, A::DryRun, &[ch('d')], &[Ms::Button("Dry run")], "a verb that changes the host: run its dry run and show the plan"),
    b(M::VerbForm, A::RunVerb, &[ch('r')], &[Ms::Button("Run")], "a verb that reads, watches or writes: run it (one that writes, or changes the host with no dry run, asks first)"),
    b(M::VerbForm, A::ShowOutput, &[ch('o')], &[Ms::Button("Output")], "the last run's output"),
    b(M::VerbForm, A::Ticket, &[ch('t')], &[Ms::Button("Ticket")], "choose the ticket"),
    b(M::VerbForm, A::Back, &[is(Key::Esc)], &[Ms::Button("Back")], "back to the list of verbs"),
];

const VERB_VALUE: &[Binding] = &[
    b(M::VerbValue, A::Canned(0), &[is(Key::F(2))], &[Ms::Canned], "fill in choice 1"),
    b(M::VerbValue, A::Canned(1), &[is(Key::F(3))], &[Ms::Canned], "fill in choice 2"),
    b(M::VerbValue, A::Canned(2), &[is(Key::F(4))], &[Ms::Canned], "fill in choice 3"),
    b(M::VerbValue, A::Canned(3), &[is(Key::F(5))], &[Ms::Canned], "fill in choice 4"),
    b(M::VerbValue, A::Canned(4), &[is(Key::F(6))], &[Ms::Canned], "fill in choice 5"),
    b(M::VerbValue, A::Canned(5), &[is(Key::F(7))], &[Ms::Canned], "fill in choice 6"),
    b(M::VerbValue, A::PageUp, &[is(Key::PageUp)], &[Ms::Button("Prev choices")], "the previous six choices"),
    b(M::VerbValue, A::PageDown, &[is(Key::PageDown)], &[Ms::Button("More choices")], "the next six choices"),
];
const VERB_OUTPUT: &[Binding] = &[
    b(M::VerbOutput, A::ScrollUp, &[is(Key::Up), ch('k')], &[Ms::WheelUp, Ms::Scrollbar], "scroll the output up a line"),
    b(M::VerbOutput, A::ScrollDown, &[is(Key::Down), ch('j')], &[Ms::WheelDown, Ms::Scrollbar], "scroll the output down a line"),
    b(M::VerbOutput, A::PageUp, &[is(Key::PageUp), ch('b')], &[Ms::Scrollbar], "the output up a page"),
    b(M::VerbOutput, A::PageDown, &[is(Key::PageDown), ch(' ')], &[Ms::Scrollbar], "the output down a page"),
    b(M::VerbOutput, A::Top, &[is(Key::Home), ch('g')], &[Ms::Button("Top")], "the output's first line"),
    b(M::VerbOutput, A::Bottom, &[is(Key::End), ch('G')], &[Ms::Button("Bottom")], "the output's last line, and follow it"),
    b(M::VerbOutput, A::Arm, &[ch('a')], &[Ms::Button("Arm")], "apply exactly the plan the dry run showed (asks first)"),
    b(M::VerbOutput, A::Stop, &[ch('s')], &[Ms::Button("Stop")], "stop a read or a watch (never an armed run, or one that writes)"),
    b(M::VerbOutput, A::Keep, &[ch('p')], &[Ms::Button("Keep")], "keep the change before its rollback (asks first)"),
    b(M::VerbOutput, A::Revert, &[ch('u')], &[Ms::Button("Revert")], "put the change back now, before its deadline (asks first)"),
    b(M::VerbOutput, A::Back, &[is(Key::Esc)], &[Ms::Button("Back")], "back to the verb's flags"),
];

const VERB_CONFIRM: &[Binding] = &[
    b(M::VerbConfirm, A::Apply, &[ch('y'), ch('Y')], &[Ms::Button("Apply")], "run what the question shows"),
    b(M::VerbConfirm, A::Cancel, &[KeyPat::Any], &[Ms::Button("Cancel"), Ms::Outside], "cancel; nothing is run"),
];

pub(crate) fn verb_apply_text() -> String {
    VERB_CONFIRM.iter().find(|b| b.action == A::Apply).and_then(|b| b.button_text()).unwrap_or_else(|| "Apply".into())
}

const QUIT: Binding = b(M::Global, A::Quit, &[ch('q')], &[Ms::Button("Quit")], "leave the view");
const NEXT_TAB: Binding = b(M::Global, A::NextTab, &[is(Key::Tab)], &[Ms::Tab], "the next tab");
const PREV_TAB: Binding = b(M::Global, A::PrevTab, &[is(Key::BackTab)], &[Ms::Tab], "the previous tab");

const POSTURE_MODE: &[Binding] = &[
    b(M::Posture, A::Reprobe, &[ch('r')], &[Ms::Button("Re-probe")], "probe the host again"),
    b(M::Posture, A::Quit, &[ch('q'), is(Key::Esc)], &[Ms::Button("Quit")], "leave the view"),
];
const POSTURE_GLOBAL: &[Binding] = &[
    QUIT,
    NEXT_TAB,
    PREV_TAB,
    b(M::Global, A::GoTab(0), &[ch('1')], &[Ms::Tab], "the posture tab"),
    b(M::Global, A::GoTab(1), &[ch('2'), ch('v')], &[Ms::Tab], "the verbs tab"),
    b(M::Global, A::Docs, &[is(Key::F(1)), ch('?'), ch('3')], &[Ms::Tab], "the docs tab"),
];

pub const POSTURE: Table = Table {
    view: "Posture view",
    groups: &[POSTURE_MODE, POSTURE_GLOBAL, VERB_LIST, VERB_FORM, VERB_VALUE, VERB_OUTPUT, VERB_CONFIRM, DOCS, TEXT],
};

pub(crate) const POSTURE_TABS: &[(&str, A)] = &[("Posture", A::GoTab(0)), ("Verbs", A::GoTab(1)), ("Docs", A::Docs)];

const FINDINGS: &[Binding] = &[
    b(M::Findings, A::Up, &[is(Key::Up), ch('k')], &[Ms::Button("Up"), Ms::WheelUp, Ms::Row, Ms::Scrollbar], "select the finding above"),
    b(M::Findings, A::Down, &[is(Key::Down), ch('j')], &[Ms::Button("Down"), Ms::WheelDown, Ms::Row, Ms::Scrollbar], "select the finding below"),
    b(M::Findings, A::PageUp, &[is(Key::PageUp)], &[Ms::Scrollbar], "select a page up"),
    b(M::Findings, A::PageDown, &[is(Key::PageDown)], &[Ms::Scrollbar], "select a page down"),
    b(M::Findings, A::Inspect, &[ch('i'), is(Key::Enter)], &[Ms::Button("Evidence")], "the selected finding's full evidence"),
    b(M::Findings, A::Fix, &[ch('f')], &[Ms::Button("Fix")], "offer the selected finding's remedy (asks first)"),
    b(M::Findings, A::Rescan, &[ch('r')], &[Ms::Button("Rescan")], "run every sweep again"),
    b(M::Findings, A::Quit, &[ch('q'), is(Key::Esc)], &[Ms::Button("Quit")], "leave the console"),
];
const EVIDENCE: &[Binding] = &[
    b(M::Evidence, A::Inspect, &[is(Key::Esc), ch('i')], &[Ms::Button("Back")], "back to the findings list"),
    b(M::Evidence, A::Up, &[is(Key::Up), ch('k')], &[Ms::Button("Prev")], "the previous finding's evidence"),
    b(M::Evidence, A::Down, &[is(Key::Down), ch('j')], &[Ms::Button("Next")], "the next finding's evidence"),
    b(M::Evidence, A::ScrollUp, &[ch('K')], &[Ms::WheelUp, Ms::Scrollbar], "scroll up a line"),
    b(M::Evidence, A::ScrollDown, &[ch('J')], &[Ms::WheelDown, Ms::Scrollbar], "scroll down a line"),
    b(M::Evidence, A::PageUp, &[is(Key::PageUp), ch('b')], &[Ms::Scrollbar], "up a page"),
    b(M::Evidence, A::PageDown, &[is(Key::PageDown), ch(' ')], &[Ms::Scrollbar], "down a page"),
    b(M::Evidence, A::Fix, &[ch('f')], &[Ms::Button("Fix")], "offer this finding's remedy (asks first)"),
    b(M::Evidence, A::Rescan, &[ch('r')], &[Ms::Button("Rescan")], "run every sweep again"),
];

const CONFIRM: &[Binding] = &[
    b(M::Confirm, A::Apply, &[ch('y'), ch('Y')], &[Ms::Button("Apply")], "apply the remedy shown"),
    b(M::Confirm, A::Cancel, &[KeyPat::Any], &[Ms::Button("Cancel"), Ms::Outside], "cancel; nothing is changed"),
];
const CONSOLE_GLOBAL: &[Binding] = &[
    QUIT,
    NEXT_TAB,
    PREV_TAB,
    b(M::Global, A::GoTab(0), &[ch('1')], &[Ms::Tab], "the findings tab"),
    b(M::Global, A::GoTab(1), &[ch('2')], &[Ms::Tab], "the evidence tab"),
    b(M::Global, A::GoTab(2), &[ch('3'), ch('v')], &[Ms::Tab], "the verbs tab"),
    b(M::Global, A::Docs, &[is(Key::F(1)), ch('?'), ch('4')], &[Ms::Tab], "the docs tab"),
];

pub const CONSOLE: Table = Table {
    view: "Findings console",
    groups: &[FINDINGS, EVIDENCE, CONFIRM, CONSOLE_GLOBAL, VERB_LIST, VERB_FORM, VERB_VALUE, VERB_OUTPUT, VERB_CONFIRM, DOCS, TEXT],
};

pub(crate) const CONSOLE_TABS: &[(&str, A)] =
    &[("Findings", A::GoTab(0)), ("Evidence", A::GoTab(1)), ("Verbs", A::GoTab(2)), ("Docs", A::Docs)];

const ALERTS: &[Binding] = &[
    b(M::Alerts, A::Up, &[is(Key::Up), ch('k')], &[Ms::Button("Up"), Ms::WheelUp, Ms::Row, Ms::Scrollbar], "select the alert above"),
    b(M::Alerts, A::Down, &[is(Key::Down), ch('j')], &[Ms::Button("Down"), Ms::WheelDown, Ms::Row, Ms::Scrollbar], "select the alert below"),
    b(M::Alerts, A::PageUp, &[is(Key::PageUp)], &[Ms::Scrollbar], "up ten alerts"),
    b(M::Alerts, A::PageDown, &[is(Key::PageDown)], &[Ms::Scrollbar], "down ten alerts"),
    b(M::Alerts, A::Open, &[is(Key::Enter)], &[Ms::Button("Open"), Ms::Row], "open the selected alert (or click it again)"),
    b(M::Alerts, A::Ack, &[ch('a')], &[Ms::Button("Ack")], "ack: you have seen it"),
    b(M::Alerts, A::Investigate, &[ch('i')], &[Ms::Button("Investigating")], "investigating: you own it"),
    b(M::Alerts, A::Resolve, &[ch('r')], &[Ms::Button("Resolve")], "resolve, with a resolution and a reason"),
    b(M::Alerts, A::Note, &[ch('n')], &[Ms::Button("Note")], "add a note"),
    b(M::Alerts, A::Reread, &[ch('g')], &[Ms::Button("Re-read")], "fold the ledger and the stores again"),
    b(M::Alerts, A::Quit, &[ch('q'), is(Key::Esc)], &[Ms::Button("Quit")], "leave the queue"),
];
const DETAIL: &[Binding] = &[
    b(M::Detail, A::Back, &[is(Key::Esc)], &[Ms::Button("Back")], "back to the alert list"),
    b(M::Detail, A::ScrollUp, &[is(Key::Up), ch('k')], &[Ms::WheelUp, Ms::Scrollbar], "scroll up a line"),
    b(M::Detail, A::ScrollDown, &[is(Key::Down), ch('j')], &[Ms::WheelDown, Ms::Scrollbar], "scroll down a line"),
    b(M::Detail, A::PageUp, &[is(Key::PageUp)], &[Ms::Scrollbar], "up ten lines"),
    b(M::Detail, A::PageDown, &[is(Key::PageDown)], &[Ms::Scrollbar], "down ten lines"),
    b(M::Detail, A::Ack, &[ch('a')], &[Ms::Button("Ack")], "ack this alert"),
    b(M::Detail, A::Investigate, &[ch('i')], &[Ms::Button("Investigating")], "investigating: you own it"),
    b(M::Detail, A::Resolve, &[ch('r')], &[Ms::Button("Resolve")], "resolve this alert"),
    b(M::Detail, A::Note, &[ch('n')], &[Ms::Button("Note")], "add a note"),
    b(M::Detail, A::Reread, &[ch('g')], &[Ms::Button("Re-read")], "fold again"),
];
const LINES: &[Binding] = &[
    b(M::Lines, A::Back, &[is(Key::Esc)], &[Ms::Button("Back")], "back to the alert list"),
    b(M::Lines, A::ScrollUp, &[is(Key::Up), ch('k')], &[Ms::WheelUp, Ms::Scrollbar], "scroll up a line"),
    b(M::Lines, A::ScrollDown, &[is(Key::Down), ch('j')], &[Ms::WheelDown, Ms::Scrollbar], "scroll down a line"),
    b(M::Lines, A::PageUp, &[is(Key::PageUp)], &[Ms::Scrollbar], "up ten lines"),
    b(M::Lines, A::PageDown, &[is(Key::PageDown)], &[Ms::Scrollbar], "down ten lines"),
    b(M::Lines, A::Reread, &[ch('g')], &[Ms::Button("Re-read")], "fold again"),
];
const RESOLVE_KIND: &[Binding] = &[
    b(M::ResolveKind, A::ResolveAs('t'), &[ch('t')], &[Ms::Button("True-positive")], "resolve as a true positive"),
    b(M::ResolveKind, A::ResolveAs('f'), &[ch('f')], &[Ms::Button("False-positive")], "resolve as a false positive"),
    b(M::ResolveKind, A::ResolveAs('b'), &[ch('b')], &[Ms::Button("Benign")], "resolve as benign"),
    b(M::ResolveKind, A::CancelEntry, &[is(Key::Esc)], &[Ms::Button("Cancel")], "give up; nothing is recorded"),
];
const QUEUE_GLOBAL: &[Binding] = &[
    QUIT,
    NEXT_TAB,
    PREV_TAB,
    b(M::Global, A::GoTab(0), &[ch('1')], &[Ms::Tab], "the alerts tab"),
    b(M::Global, A::GoTab(1), &[ch('2'), ch('h')], &[Ms::Tab], "the hosts tab"),
    b(M::Global, A::GoTab(2), &[ch('3'), ch('c')], &[Ms::Tab], "the clusters tab"),
    b(M::Global, A::GoTab(3), &[ch('4'), ch('v')], &[Ms::Tab], "the verbs tab"),
    b(M::Global, A::Docs, &[is(Key::F(1)), ch('?'), ch('5')], &[Ms::Tab], "the docs tab"),
];

pub const QUEUE: Table = Table {
    view: "Collector queue",
    groups: &[ALERTS, DETAIL, LINES, RESOLVE_KIND, QUEUE_GLOBAL, VERB_LIST, VERB_FORM, VERB_VALUE, VERB_OUTPUT, VERB_CONFIRM, DOCS, REASON, TEXT],
};

pub(crate) const QUEUE_TABS: &[(&str, A)] = &[
    ("Alerts", A::GoTab(0)),
    ("Hosts", A::GoTab(1)),
    ("Clusters", A::GoTab(2)),
    ("Verbs", A::GoTab(3)),
    ("Docs", A::Docs),
];

pub const ALL: &[&Table] = &[&CONSOLE, &QUEUE, &POSTURE];
