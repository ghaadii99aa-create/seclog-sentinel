"""Self-contained HTML and JSON report generation.

The HTML report has no external assets (no CDN, fonts or scripts) so it can be opened
offline or attached to a ticket. Every value that originates from a log file is
HTML-escaped, because usernames in auth logs are attacker-controlled.
"""

from __future__ import annotations

import json
from datetime import datetime
from html import escape
from typing import Optional

from . import __version__
from .models import Analysis, Finding

_CSS = """
:root{--bg:#f5f7fa;--panel:#fff;--text:#1b2733;--muted:#5d6b7a;--line:#e1e6ec;
--critical:#b3122b;--high:#d9480f;--medium:#b7791f;--low:#2b6cb0;--ok:#2f855a;--fail:#e0525e;}
@media (prefers-color-scheme:dark){:root{--bg:#0f1720;--panel:#17212c;--text:#e6edf3;
--muted:#93a1b0;--line:#26323f;--critical:#ff5c70;--high:#ff8a4c;--medium:#e8b44d;
--low:#63a4ff;--ok:#4cc38a;--fail:#ff6b78;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
.wrap{max-width:1040px;margin:0 auto;padding:32px 20px 56px}
h1{font-size:26px;margin:0 0 4px} h2{font-size:18px;margin:36px 0 12px}
.sub{color:var(--muted);font-size:14px;margin:0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:24px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kpi b{display:block;font-size:26px;line-height:1.2} .kpi span{color:var(--muted);font-size:13px}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:5px;
border-radius:10px;padding:16px 18px;margin-bottom:14px}
.finding h3{margin:0;font-size:16px;display:inline}
.finding header{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:6px}
.sev-critical{border-left-color:var(--critical)} .sev-high{border-left-color:var(--high)}
.sev-medium{border-left-color:var(--medium)} .sev-low{border-left-color:var(--low)}
.badge{color:#fff;font-size:11px;font-weight:700;letter-spacing:.05em;padding:2px 8px;border-radius:99px}
.badge.critical{background:var(--critical)} .badge.high{background:var(--high)}
.badge.medium{background:var(--medium)} .badge.low{background:var(--low)}
.meta{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:13px;color:var(--muted);margin:8px 0}
.meta code,td code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--text)}
.rec{font-size:14px;margin:8px 0 0}
a{color:var(--low)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
border-radius:10px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
tr:last-child td{border-bottom:0}
.chart{display:flex;gap:4px;align-items:flex-end;height:150px;background:var(--panel);
border:1px solid var(--line);border-radius:10px;padding:14px 12px 8px}
.col{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%}
.stack{width:100%;display:flex;flex-direction:column-reverse;justify-content:flex-start;flex:1}
.seg-f{background:var(--fail);border-radius:2px 2px 0 0} .seg-a{background:var(--ok)}
.lbl{font-size:10px;color:var(--muted);margin-top:4px}
.legend{font-size:12px;color:var(--muted);margin-top:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin:0 4px 0 12px}
.clean{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;color:var(--ok)}
footer{margin-top:40px;color:var(--muted);font-size:12px}
"""


def _fmt(ts: Optional[datetime]) -> str:
    return ts.strftime("%Y-%m-%d %H:%M") if ts else "n/a"


def _finding_html(f: Finding) -> str:
    technique_path = f.mitre_id.replace(".", "/")
    users = ", ".join(escape(u) for u in f.users[:8])
    if len(f.users) > 8:
        users += f" (+{len(f.users) - 8} more)"
    return f"""
<article class="finding sev-{escape(f.severity)}">
  <header><span class="badge {escape(f.severity)}">{escape(f.severity.upper())}</span>
  <h3>{escape(f.title)}</h3></header>
  <p style="margin:0">{escape(f.description)}</p>
  <div class="meta">
    <span>Source IP: <code>{escape(f.ip)}</code></span>
    <span>Accounts: <code>{users}</code></span>
    <span>Events: <code>{f.count}</code></span>
    <span>MITRE ATT&amp;CK: <a href="https://attack.mitre.org/techniques/{escape(technique_path)}/"
      target="_blank" rel="noopener noreferrer">{escape(f.mitre_id)} {escape(f.mitre_name)}</a></span>
  </div>
  <p class="rec"><strong>Recommended action:</strong> {escape(f.recommendation)}</p>
</article>"""


def _chart_html(analysis: Analysis) -> str:
    peak = max((h["failed"] + h["accepted"] for h in analysis.hourly), default=0) or 1
    columns = []
    for h in analysis.hourly:
        total = h["failed"] + h["accepted"]
        failed_pct = h["failed"] / peak * 100
        accepted_pct = h["accepted"] / peak * 100
        tip = f"{h['hour']:02d}:00 - {h['failed']} failed, {h['accepted']} accepted"
        columns.append(
            f'<div class="col" title="{escape(tip)}"><div class="stack">'
            f'<div style="flex:0 0 {failed_pct:.1f}%" class="seg-f"></div>'
            f'<div style="flex:0 0 {accepted_pct:.1f}%" class="seg-a"></div>'
            f'</div><div class="lbl">{h["hour"]:02d}</div></div>'
            if total
            else f'<div class="col" title="{escape(tip)}"><div class="stack"></div>'
            f'<div class="lbl">{h["hour"]:02d}</div></div>'
        )
    return (
        '<div class="chart">' + "".join(columns) + "</div>"
        '<div class="legend"><i style="background:var(--fail)"></i>Failed'
        '<i style="background:var(--ok)"></i>Accepted &nbsp;(by hour of day)</div>'
    )


def render_html(
    analysis: Analysis,
    source_name: str = "auth.log",
    generated_at: Optional[datetime] = None,
) -> str:
    generated = generated_at or datetime.now()
    counts = analysis.severity_counts()

    if analysis.findings:
        findings_html = "".join(_finding_html(f) for f in analysis.findings)
    else:
        findings_html = '<div class="clean">No suspicious activity detected with the current thresholds.</div>'

    rows = "".join(
        f"<tr><td><code>{escape(s['ip'])}</code></td><td>{s['failures']}</td>"
        f"<td>{s['distinct_users']}</td></tr>"
        for s in analysis.top_sources
    ) or '<tr><td colspan="3">No failed logins.</td></tr>'

    kpis = [
        (analysis.total_events, "Auth events"),
        (analysis.failed, "Failed logins"),
        (analysis.accepted, "Accepted logins"),
        (analysis.unique_ips, "Unique source IPs"),
        (len(analysis.findings), "Findings"),
    ]
    kpi_html = "".join(f'<div class="kpi"><b>{value}</b><span>{label}</span></div>' for value, label in kpis)

    summary = (
        f"critical {counts['critical']} · high {counts['high']} · "
        f"medium {counts['medium']} · low {counts['low']}"
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecLog Sentinel Report</title><style>{_CSS}</style></head>
<body><div class="wrap">
<h1>SecLog Sentinel Report</h1>
<p class="sub">Source: {escape(source_name)} · Period: {_fmt(analysis.start)} to {_fmt(analysis.end)}
 · Generated: {_fmt(generated)}</p>
<div class="kpis">{kpi_html}</div>

<h2>Findings <span class="sub">({escape(summary)})</span></h2>
{findings_html}

<h2>Top sources of failed logins</h2>
<table><thead><tr><th>Source IP</th><th>Failed logins</th><th>Distinct accounts</th></tr></thead>
<tbody>{rows}</tbody></table>

<h2>Activity by hour</h2>
{_chart_html(analysis)}

<footer>Generated by SecLog Sentinel v{__version__}. {analysis.ignored_lines} non-auth or
unparseable line(s) were ignored.</footer>
</div></body></html>
"""


def render_json(analysis: Analysis) -> str:
    return json.dumps(analysis.to_dict(), indent=2, ensure_ascii=False)
