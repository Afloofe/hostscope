use hemostat_sensor_freebsd::verdict::{BoxOwned, Standing};

use crate::render::{h, jesc};

fn jstr(s: &str) -> String {
    format!("\"{}\"", jesc(s))
}

fn jlist(v: &[String]) -> String {
    format!("[{}]", v.iter().map(|s| jstr(s)).collect::<Vec<_>>().join(","))
}

pub(crate) fn render_box_owned(o: &mut String, b: &BoxOwned) {
    use std::fmt::Write as _;
    let _ = writeln!(
        o,
        "\n  THE FIREWALL'S OWN CONNECTIONS — {} state(s) with an end on this box: {} CONTRADICTION, {} unknown, {} held by a socket",
        b.flows.len(),
        b.count(Standing::Contradiction),
        b.count(Standing::Unknown),
        b.count(Standing::Accounted)
    );
    for f in b.flows.iter().filter(|f| f.standing != Standing::Accounted) {
        let _ = writeln!(o, "    {:<13} {}", f.standing.label(), h(&f.state));
        let _ = writeln!(o, "                  {}", h(&f.basis));
    }
}

pub(crate) fn box_owned_json(b: &BoxOwned) -> String {
    use hemostat_sensor_freebsd::telemetry::filterlog::proto;
    let flows: Vec<String> = b
        .flows
        .iter()
        .map(|f| {
            format!(
                "{{\"standing\":{},\"proto\":{},\"local\":{},\"peer\":{},\"inbound\":{},\"state\":{},\"basis\":{}}}",
                jstr(f.standing.label()),
                jstr(&proto::name(f.proto)),
                jstr(&f.local.to_string()),
                jstr(&f.peer.to_string()),
                f.inbound,
                jstr(&f.state),
                jstr(&f.basis)
            )
        })
        .collect();
    format!("{{\"flows\":[{}],\"limits\":{}}}", flows.join(","), jlist(&b.limits))
}
