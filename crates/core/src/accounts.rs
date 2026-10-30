pub const HARD_PROTECT: &[&str] = &["whiteteam", "dd-agent", "ddagentuser", "datadog"];

pub fn is_hard_protected(name: &str) -> bool {
    HARD_PROTECT.iter().any(|p| p.eq_ignore_ascii_case(name))
}
