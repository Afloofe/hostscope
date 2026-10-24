use crate::queue::{suggestion, Alert, Queue, Sev};
use crate::heartbeat::secs;
use crate::{hex, js, span, utc};

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn short(h: &[u8; 32]) -> String {
    hex(h).chars().take(12).collect()
}

fn sev_class(s: Sev) -> &'static str {
    match s {
        Sev::Critical => "crit",
        Sev::Warn => "warn",
        Sev::Note | Sev::Info => "note",
    }
}

const STYLE: &str = "\
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1b1b;--dim:#666;--rule:#ddd;--crit:#b00020;--warn:#8a5a00;--note:#555;--band:#f4f4f4}\
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#e8e8e8;--dim:#9a9a9a;--rule:#333;--crit:#ff6b7a;--warn:#e0b050;--note:#aaa;--band:#1e1e1e}}\
body{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;margin:0;padding:16px;max-width:1200px}\
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:24px 0 8px;border-bottom:1px solid var(--rule)}\
.dim{color:var(--dim)}table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}\
th,td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--rule);vertical-align:top}\
th{font-weight:600;white-space:nowrap}td.mono,code{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}\
.crit{color:var(--crit);font-weight:700}.warn{color:var(--warn);font-weight:600}.note{color:var(--note)}\
details{border:1px solid var(--rule);border-radius:4px;margin:6px 0;padding:6px 10px;background:var(--band)}\
summary{cursor:pointer}.counts span{margin-right:16px}";

pub fn to_html(q: &Queue, engagement: &str, generated_ns: i64, ledger_key: &str) -> String {
    let mut o = String::new();
    o.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">");
    o.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");

    o.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">");
    o.push_str("<title>HEMOSTAT alert queue</title><style>");
    o.push_str(STYLE);
    o.push_str("</style></head><body>\n");
    o.push_str(&format!(
        "<h1>HEMOSTAT alert queue</h1><p class=\"dim\">engagement <code>{}</code> · written {} by the collector's clock · \
         {} ledger run(s) under ledger key <code>{}</code></p>\n",
        esc(engagement),
        esc(&utc(generated_ns)),
        q.ledger_runs,
        esc(ledger_key)
    ));
    o.push_str(&format!(
        "<p class=\"counts\"><span class=\"crit\">{} CRITICAL</span><span class=\"warn\">{} WARN</span>\
         <span class=\"note\">{} note</span><span class=\"dim\">{} host(s) · {} inventory row(s) not raised</span></p>\n",
        q.alerts.iter().filter(|a| a.max_sev == Sev::Critical).count(),
        q.alerts.iter().filter(|a| a.max_sev == Sev::Warn).count(),
        q.alerts.iter().filter(|a| a.max_sev <= Sev::Note).count(),
        q.hosts.len(),
        q.inventory_rows
    ));
    o.push_str(
        "<p class=\"dim\">The queue changes queue state only: nothing here reached a host. A resolved alert keeps its \
         grade and its sightings; severity is the highest the alert was ever graded.</p>\n",
    );

    if !q.anomalies.is_empty() {
        o.push_str("<h2 class=\"crit\">What the fold could not reconcile</h2><ul>");
        for a in &q.anomalies {
            o.push_str(&format!("<li>{}</li>", esc(a)));
        }
        o.push_str("</ul>\n");
    }

    o.push_str("<h2>Hosts</h2><table><tr><th>host</th><th>last heard</th><th>last store</th><th>pin</th>\
                <th>variant</th><th>stores</th><th>findings readable</th><th>gaps in latest</th>\
                <th>carried, not judged here</th><th>heartbeat</th><th>clock offset</th></tr>\n");
    for h in &q.hosts {
        let gaps = if h.gaps.is_empty() {
            "none".to_string()
        } else {
            h.gaps
                .iter()
                .map(|g| format!("{} ({}): {}", esc(&g.source), if g.partial { "in part" } else { "did not run" }, esc(&g.reason)))
                .collect::<Vec<_>>()
                .join("<br>")
        };
        let carried = if h.carried.is_empty() {
            "none".to_string()
        } else {
            h.carried
                .iter()
                .map(|c| format!("{} ({} store(s){}): {}", esc(&c.kind), c.stores, if c.raised { ", raised" } else { "" }, esc(&c.what)))
                .collect::<Vec<_>>()
                .join("<br>")
        };
        let (beat, clock) = match &h.beacon {
            None => ("none recorded".to_string(), "not measured".to_string()),
            Some(b) => (
                format!(
                    "{} · last {} · {} missing, {} restart(s), {} replay(s)",
                    esc(&b.state),
                    esc(&utc(b.last_ns)),
                    b.missing,
                    b.restarts,
                    b.stale
                ),
                match (b.offset_ns, b.spread_ns) {
                    (Some(o), Some(s)) => format!("{} ± {} · {} step(s)", secs(o), secs(s).trim_start_matches('+'), b.jumps),
                    _ => "not measured".to_string(),
                },
            ),
        };
        o.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td>{} {}</td><td>{}</td>\
             <td>{}</td><td>{}</td><td>{carried}</td><td>{beat}</td><td>{clock}</td></tr>\n",
            hex(&h.host),
            esc(&if h.last_heard_ns == 0 { "never".to_string() } else { utc(h.last_heard_ns) }),
            h.last_store.map_or(String::new(), |g| short(&g)),
            esc(&h.pin),
            esc(&h.variant),
            esc(&h.version),
            h.stores,
            esc(&h.readable),
            gaps
        ));
    }
    o.push_str("</table>\n");
    coverage_html(&mut o, q);

    o.push_str("<h2>Alerts</h2><table><tr><th>id</th><th>severity</th><th>host</th><th>source</th><th>subject</th>\
                <th>sightings</th><th>state</th><th>owner</th><th>first seen</th><th>age</th></tr>\n");
    for a in &q.alerts {
        let grade = if a.cur_sev == a.max_sev {
            a.max_sev.token().to_string()
        } else {
            format!("{} (now {})", a.max_sev.token(), a.cur_sev.token())
        };
        o.push_str(&format!(
            "<tr><td class=\"mono\"><a href=\"#a{id}\">{id}</a></td><td class=\"{}\">{}</td><td class=\"mono\">{}</td>\
             <td>{}</td><td>{}</td><td>{}</td><td>{}{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            sev_class(a.max_sev),
            esc(&grade),
            short(&a.host),
            esc(&a.source),
            esc(&a.subject),
            a.sightings.len(),
            esc(&a.state.name()),
            if a.absent_from_latest { " · absent from latest" } else { "" },
            esc(a.owner.as_deref().unwrap_or("")),
            esc(&utc(a.first_ns)),
            esc(&span(generated_ns - a.first_ns)),
            id = esc(&a.id)
        ));
    }
    o.push_str("</table>\n");
    joins_html(&mut o, q);
    o.push_str("<h2>Detail</h2>\n");
    for a in &q.alerts {
        detail_html(&mut o, q, a);
    }
    o.push_str("</body></html>\n");
    o
}

fn coverage_html(o: &mut String, q: &Queue) {
    o.push_str("<h2>Coverage (J4)</h2><table><tr><th>host</th><th>status</th><th>why</th></tr>\n");
    for c in &q.joins.coverage {
        let class = match c.status {
            "never heard from" | "silent" => "crit",
            "gaps" | "blind to joins" => "warn",
            _ => "note",
        };
        o.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td class=\"{class}\">{}</td><td>{}</td></tr>\n",
            esc(&c.label),
            esc(c.status),
            c.lines.iter().map(|l| esc(l)).collect::<Vec<_>>().join("<br>")
        ));
    }
    o.push_str("</table>\n");
}

fn joins_html(o: &mut String, q: &Queue) {
    let j = &q.joins;
    o.push_str("<h2>Joins</h2><p class=\"dim\">Derived across hosts from the stores the collector verified; nobody named \
                the stores. Each host's alerts stay its own; a join is never a reason to act.</p>\n");
    o.push_str("<h3>J1 flow: each firewall capture × each host behind it</h3>");
    if j.flows.is_empty() {
        o.push_str("<p>no pair: no firewall capture and flow export of a host behind it, the capture taken after the export</p>");
    } else {
        o.push_str("<table><tr><th>firewall</th><th>host</th><th>stores</th><th>CONTRADICTION</th><th>agreement</th>\
                    <th>UNKNOWN</th><th>clocks</th><th>what neither side could see</th></tr>");
        for p in &j.flows {
            o.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{} × {}</td><td class=\"{}\">{}</td>\
                 <td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                short(&p.fw),
                short(&p.host),
                short(&p.fw_store),
                short(&p.host_store),
                if p.counts.0 > 0 { "crit" } else { "note" },
                p.counts.0,
                p.counts.1,
                p.counts.2,
                esc(&p.clock),
                p.unknowns.iter().take(12).map(|u| esc(u)).collect::<Vec<_>>().join("<br>")
            ));
        }
        o.push_str("</table>");
    }
    o.push_str("<h3>J2 spread: one thing on two hosts or more</h3>");
    if j.clusters.is_empty() {
        o.push_str("<p>none</p>");
    }
    for c in &j.clusters {
        o.push_str(&format!(
            "<details><summary><span class=\"{}\">{}</span> the {} <code>{}</code> on {} host(s)</summary><ul>",
            sev_class(c.severity),
            c.severity.token(),
            esc(c.entity.kind()),
            esc(c.entity.value()),
            c.members.len()
        ));
        for m in &c.members {
            let flagged: Vec<String> =
                m.flagged.iter().map(|(id, s)| format!("<a href=\"#a{id}\">{id}</a> {}", s.token(), id = esc(id))).collect();
            o.push_str(&format!(
                "<li>{} — {}{}</li>",
                esc(&m.label),
                if flagged.is_empty() { "nothing here flagged it".to_string() } else { format!("flagged: {}", flagged.join(", ")) },
                if m.present.is_empty() { String::new() } else { format!("; recorded at {}", m.present.iter().map(|p| esc(p)).collect::<Vec<_>>().join(", ")) }
            ));
        }
        o.push_str("</ul></details>");
    }
    o.push_str("<h3>J3 lateral: a session to a host, and a new key, account or persistence there</h3>");
    if j.chains.is_empty() {
        o.push_str("<p>none</p>");
    }
    for c in &j.chains {
        o.push_str(&format!(
            "<p class=\"warn\">{} → {} port {} ({})</p><p class=\"dim\">{} · alert <a href=\"#a{id}\">{id}</a></p>",
            short(&c.from),
            short(&c.to),
            c.port,
            esc(c.service),
            esc(&c.window),
            id = esc(&c.alert)
        ));
    }
    if !j.notes.is_empty() {
        o.push_str("<h3>What the joins could not draw</h3><ul>");
        for n in &j.notes {
            o.push_str(&format!("<li>{}</li>", esc(n)));
        }
        o.push_str("</ul>");
    }
    o.push('\n');
}

fn detail_html(o: &mut String, q: &Queue, a: &Alert) {
    o.push_str(&format!(
        "<details id=\"a{}\"><summary><span class=\"{}\">{}</span> {} · {} · <code>{}</code></summary>\n",
        esc(&a.id),
        sev_class(a.max_sev),
        a.max_sev.token(),
        esc(&a.source),
        esc(&a.subject),
        esc(&a.id)
    ));
    o.push_str(&format!("<p>host <code>{}</code> · state {} </p>", hex(&a.host), esc(&a.state.name())));
    if let Some(basis) = &a.judged_here {
        o.push_str(&format!(
            "<p class=\"dim\">judged by the collector from the raw input the store sealed, against {}</p>",
            esc(basis)
        ));
    }
    for e in &a.evidence {
        o.push_str(&format!(
            "<p>[{}] {}{}{}</p>",
            esc(&e.severity),
            esc(&e.what),
            if e.locus.is_empty() { String::new() } else { format!("<br><span class=\"dim\">at</span> <code>{}</code>", esc(&e.locus)) },
            if e.why.is_empty() { String::new() } else { format!("<br><span class=\"dim\">{}</span>", esc(&e.why)) },
        ));
    }
    let joined = q.joins_of(a);
    if !a.basis.is_empty() || !joined.is_empty() {
        o.push_str("<p class=\"dim\">join basis:<br>");
        o.push_str(&a.basis.iter().chain(joined.iter()).map(|l| esc(l)).collect::<Vec<_>>().join("<br>"));
        o.push_str("</p>");
    }
    o.push_str("<table><tr><th>sighting</th><th>store</th><th>records</th><th>grade</th><th>evidence digest</th><th>ledger run</th></tr>");
    for s in &a.sightings {
        o.push_str(&format!(
            "<tr><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            esc(&utc(s.at_ns)),
            esc(&s.store),
            s.seqs.iter().map(u64::to_string).collect::<Vec<_>>().join(", "),
            s.severity.token(),
            hex(&s.digest).chars().take(16).collect::<String>(),
            s.ledger_run
        ));
    }
    o.push_str("</table>");
    if !a.history.is_empty() {
        o.push_str("<table><tr><th>when</th><th>who</th><th>did</th><th>from → to</th><th>reason</th><th>ledger run</th></tr>");
        for e in &a.history {
            o.push_str(&format!(
                "<tr><td>{}</td><td>{}{}</td><td>{}</td><td>{} → {}</td><td>{}</td><td>{}</td></tr>",
                esc(&utc(e.at_ns)),
                esc(&e.actor),
                if e.owner_matches { "" } else { " <span class=\"crit\">(run not owned by this uid)</span>" },
                esc(&e.action),
                esc(&e.from),
                esc(&e.to),
                esc(&e.reason),
                e.ledger_run
            ));
        }
        o.push_str("</table>");
    }
    let (verb, ticket) = suggestion(a);
    o.push_str(&format!(
        "<p class=\"dim\">on the host: <code>{}</code><br>a change needs: <code>{}</code></p></details>\n",
        esc(&verb),
        esc(&ticket)
    ));
}

pub fn to_jsonl(q: &Queue, engagement: &str, generated_ns: i64) -> String {
    let mut o = format!(
        "{{\"record\":\"queue\",\"engagement\":{},\"generated_ns\":{generated_ns},\"ledger_runs\":{},\"alerts\":{},\
         \"hosts\":{},\"anomalies\":[{}]}}\n",
        js(engagement),
        q.ledger_runs,
        q.alerts.len(),
        q.hosts.len(),
        q.anomalies.iter().map(|a| js(a)).collect::<Vec<_>>().join(",")
    );
    for h in &q.hosts {
        let gaps: Vec<String> = h
            .gaps
            .iter()
            .map(|g| format!("{{\"source\":{},\"partial\":{},\"reason\":{}}}", js(&g.source), g.partial, js(&g.reason)))
            .collect();
        o.push_str(&format!(
            "{{\"record\":\"host\",\"host\":\"{}\",\"last_heard_ns\":{},\"last_store\":{},\"pin\":{},\"variant\":{},\
             \"stores\":{},\"readable\":{},\"gaps\":[{}],\"carried\":[{}],\"beacon\":{}}}\n",
            hex(&h.host),
            h.last_heard_ns,
            h.last_store.map_or("null".to_string(), |g| format!("\"{}\"", hex(&g))),
            js(&h.pin),
            js(&h.variant),
            h.stores,
            js(&h.readable),
            gaps.join(","),
            h.carried
                .iter()
                .map(|c| format!(
                    "{{\"kind\":{},\"stores\":{},\"raised\":{},\"what\":{}}}",
                    js(&c.kind),
                    c.stores,
                    c.raised,
                    js(&c.what)
                ))
                .collect::<Vec<_>>()
                .join(","),
            h.beacon.as_ref().map_or("null".to_string(), |b| {
                let opt = |v: Option<i64>| v.map_or("null".to_string(), |x| x.to_string());
                format!(
                    "{{\"agent\":{},\"state\":{},\"as_of_ns\":{},\"last_ns\":{},\"run\":{},\"seq\":{},\"received\":{},\
                     \"missing\":{},\"restarts\":{},\"stale\":{},\"offset_ns\":{},\"spread_ns\":{},\"window\":{},\"jumps\":{}}}",
                    js(&b.agent),
                    js(&b.state),
                    b.as_of_ns,
                    b.last_ns,
                    js(&b.run),
                    b.seq,
                    b.received,
                    b.missing,
                    b.restarts,
                    b.stale,
                    opt(b.offset_ns),
                    opt(b.spread_ns),
                    b.window,
                    b.jumps
                )
            })
        ));
    }
    for a in &q.alerts {
        let sightings: Vec<String> = a
            .sightings
            .iter()
            .map(|s| {
                format!(
                    "{{\"store\":{},\"seqs\":[{}],\"at_ns\":{},\"severity\":\"{}\",\"digest\":\"{}\",\"ledger_run\":{}}}",
                    js(&s.store),
                    s.seqs.iter().map(u64::to_string).collect::<Vec<_>>().join(","),
                    s.at_ns,
                    s.severity.token(),
                    hex(&s.digest),
                    s.ledger_run
                )
            })
            .collect();
        let history: Vec<String> = a
            .history
            .iter()
            .map(|e| {
                format!(
                    "{{\"at_ns\":{},\"actor\":{},\"action\":{},\"from\":{},\"to\":{},\"reason\":{},\"ledger_run\":{},\
                     \"owner_matches\":{}}}",
                    e.at_ns,
                    js(&e.actor),
                    js(&e.action),
                    js(&e.from),
                    js(&e.to),
                    js(&e.reason),
                    e.ledger_run,
                    e.owner_matches
                )
            })
            .collect();
        let evidence: Vec<String> = a
            .evidence
            .iter()
            .map(|e| format!("{{\"severity\":{},\"locus\":{},\"what\":{},\"why\":{}}}", js(&e.severity), js(&e.locus), js(&e.what), js(&e.why)))
            .collect();
        o.push_str(&format!(
            "{{\"record\":\"alert\",\"id\":\"{}\",\"host\":\"{}\",\"source\":{},\"subject\":{},\"origin\":\"{}\",\
             \"severity\":\"{}\",\"current\":\"{}\",\"state\":{},\"owner\":{},\"first_ns\":{},\"last_ns\":{},\
             \"absent_from_latest\":{},\"judged_here\":{},\"basis\":[{}],\"joins\":[{}],\"sightings\":[{}],\"history\":[{}],\
             \"evidence\":[{}]}}\n",
            a.id,
            hex(&a.host),
            js(&a.source),
            js(&a.subject),
            match a.origin {
                crate::queue::Origin::Finding => "finding",
                crate::queue::Origin::Collector => "collector",
                crate::queue::Origin::Join => "join",
            },
            a.max_sev.token(),
            a.cur_sev.token(),
            js(&a.state.name()),
            a.owner.as_deref().map_or("null".to_string(), js),
            a.first_ns,
            a.last_ns,
            a.absent_from_latest,
            a.judged_here.as_deref().map_or("null".to_string(), js),
            a.basis.iter().map(|b| js(b)).collect::<Vec<_>>().join(","),
            q.joins_of(a).iter().map(|b| js(b)).collect::<Vec<_>>().join(","),
            sightings.join(","),
            history.join(","),
            evidence.join(",")
        ));
    }
    joins_jsonl(&mut o, q);
    o
}

fn joins_jsonl(o: &mut String, q: &Queue) {
    let list = |v: &[String]| v.iter().map(|x| js(x)).collect::<Vec<_>>().join(",");
    for c in &q.joins.coverage {
        o.push_str(&format!(
            "{{\"record\":\"coverage\",\"host\":\"{}\",\"label\":{},\"status\":{},\"why\":[{}]}}\n",
            hex(&c.host),
            js(&c.label),
            js(c.status),
            list(&c.lines)
        ));
    }
    for p in &q.joins.flows {
        o.push_str(&format!(
            "{{\"record\":\"flow-pair\",\"firewall\":\"{}\",\"host\":\"{}\",\"firewall_store\":\"{}\",\"host_store\":\"{}\",\
             \"contradictions\":{},\"agreements\":{},\"unknown\":{},\"clock\":{},\"recognised\":[{}],\"unknowns\":[{}]}}\n",
            hex(&p.fw),
            hex(&p.host),
            hex(&p.fw_store),
            hex(&p.host_store),
            p.counts.0,
            p.counts.1,
            p.counts.2,
            js(&p.clock),
            list(&p.recognised),
            list(&p.unknowns)
        ));
    }
    for c in &q.joins.clusters {
        let members: Vec<String> = c
            .members
            .iter()
            .map(|m| {
                format!(
                    "{{\"host\":\"{}\",\"label\":{},\"flagged\":[{}],\"present\":[{}],\"spread_alert\":{}}}",
                    hex(&m.host),
                    js(&m.label),
                    m.flagged.iter().map(|(id, s)| format!("{{\"alert\":{},\"severity\":\"{}\"}}", js(id), s.token())).collect::<Vec<_>>().join(","),
                    list(&m.present),
                    m.spread.as_deref().map_or("null".to_string(), js)
                )
            })
            .collect();
        o.push_str(&format!(
            "{{\"record\":\"cluster\",\"kind\":{},\"value\":{},\"severity\":\"{}\",\"members\":[{}]}}\n",
            js(c.entity.kind()),
            js(c.entity.value()),
            c.severity.token(),
            members.join(",")
        ));
    }
    for c in &q.joins.chains {
        o.push_str(&format!(
            "{{\"record\":\"chain\",\"from\":\"{}\",\"to\":\"{}\",\"port\":{},\"service\":{},\"alert\":{},\"raised\":[{}],\"window\":{}}}\n",
            hex(&c.from),
            hex(&c.to),
            c.port,
            js(c.service),
            js(&c.alert),
            list(&c.raised),
            js(&c.window)
        ));
    }
    if !q.joins.notes.is_empty() {
        o.push_str(&format!("{{\"record\":\"join-notes\",\"notes\":[{}]}}\n", list(&q.joins.notes)));
    }
}
