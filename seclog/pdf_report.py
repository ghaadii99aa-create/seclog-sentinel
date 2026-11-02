"""Branded PDF report built with ReportLab.

Every number and chart comes from the :class:`Analysis` being reported. Text that originates from
the log (usernames, file names) is XML-escaped before it reaches a Paragraph and reduced to the
Latin-1 range, because the built-in PDF fonts cannot draw other scripts and a stray markup
character in a username must not be able to break the layout.
"""

from __future__ import annotations

import io
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple
from xml.sax.saxutils import escape

from . import __version__
from .analyzer import events_for_finding
from .models import Analysis

try:  # ReportLab is an optional dependency of the package (the web app requires it)
    from reportlab.graphics.shapes import Circle, Drawing, Line, Rect, String, Wedge
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        KeepTogether,
        NextPageTemplate,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - exercised only where ReportLab is missing
    AVAILABLE = False

NAVY = "#1f2a36"      # dark slate: headings and the brand mark
PANEL = "#f3f5f7"     # very light grey for table headers
ACCENT = "#46688c"    # the single accent: muted steel blue
INK = "#1c2229"
MUTED = "#5f6b78"
RULE = "#d3d9df"
# Red is reserved for critical findings and orange for high; the rest stay neutral.
SEVERITY = {"critical": "#b3261e", "high": "#c2661a", "medium": "#46688c", "low": "#7b8794"}
FAILED_COLOR = "#46688c"
OK_COLOR = "#aab4be"
SUSPICIOUS_COLOR = "#46688c"
MAX_EVIDENCE_ROWS = 5
MAX_APPENDIX_ROWS = 40
MAX_FINDINGS_IN_PDF = 60


class PdfUnavailable(RuntimeError):
    """ReportLab is not installed."""


def safe(text: Any, limit: int = 400) -> str:
    """Escape for Paragraph markup and keep only characters the built-in fonts can draw."""
    value = "" if text is None else str(text)
    value = "".join(ch if (ch.isprintable() and ord(ch) < 256) else "?" for ch in value)
    return escape(value[:limit])


def _hex(value: str):
    return colors.HexColor(value)


# --------------------------------------------------------------------------- charts


def _label(drawing, x, y, text, size=8, color=MUTED, anchor="start", bold=False):
    drawing.add(
        String(
            x, y, safe(text, 60), fontSize=size, fillColor=_hex(color), textAnchor=anchor,
            fontName="Helvetica-Bold" if bold else "Helvetica",
        )
    )


def bar_chart(rows: Sequence[Tuple[str, float, str]], width: float, row_height: float = 17) -> "Drawing":
    """Horizontal bars. ``rows`` are (label, value, hex colour)."""
    height = max(row_height * len(rows) + 4, 24)
    drawing = Drawing(width, height)
    if not rows:
        _label(drawing, 0, height / 2, "No data")
        return drawing
    peak = max(value for _, value, _ in rows) or 1
    label_w, value_w = 118, 34
    track = width - label_w - value_w
    for i, (name, value, color) in enumerate(rows):
        y = height - (i + 1) * row_height + 2
        _label(drawing, 0, y + 3, name, 8.5, INK)
        drawing.add(Rect(label_w, y, track, 10, fillColor=_hex("#eaf0f6"), strokeColor=None))
        if value:
            drawing.add(Rect(label_w, y, max(track * value / peak, 2), 10, fillColor=_hex(color), strokeColor=None))
        _label(drawing, width, y + 3, f"{int(value):,}", 8.5, INK, "end", True)
    return drawing


def donut(failed: int, accepted: int, size: float = 120) -> "Drawing":
    """Failed vs accepted logins as a donut with the total in the middle."""
    drawing = Drawing(size, size)
    total = failed + accepted
    cx = cy = size / 2
    radius = size / 2 - 2
    if total == 0:
        drawing.add(Circle(cx, cy, radius, fillColor=_hex("#eaf0f6"), strokeColor=None))
    elif failed == 0 or accepted == 0:
        drawing.add(Circle(cx, cy, radius, fillColor=_hex(FAILED_COLOR if failed else OK_COLOR), strokeColor=None))
    else:
        sweep = 360.0 * failed / total
        drawing.add(Wedge(cx, cy, radius, 90 - sweep, 90, fillColor=_hex(FAILED_COLOR), strokeColor=colors.white, strokeWidth=1))
        drawing.add(Wedge(cx, cy, radius, 90, 90 + 360 - sweep, fillColor=_hex(OK_COLOR), strokeColor=colors.white, strokeWidth=1))
    drawing.add(Circle(cx, cy, radius * 0.58, fillColor=colors.white, strokeColor=None))
    _label(drawing, cx, cy + 1, f"{total:,}", 13, INK, "middle", True)
    _label(drawing, cx, cy - 10, "events", 7.5, MUTED, "middle")
    return drawing


def column_chart(
    series: Sequence[Dict[str, Any]], keys: Sequence[Tuple[str, str]], width: float, height: float = 110,
    label_every: int = 1, label_fmt=lambda item: str(item.get("label", "")),
) -> "Drawing":
    """Stacked vertical columns. ``keys`` are (field name, hex colour), drawn bottom to top."""
    drawing = Drawing(width, height + 16)
    if not series:
        _label(drawing, 0, height / 2, "No data")
        return drawing
    totals = [sum(item.get(k, 0) for k, _ in keys) for item in series]
    peak = max(totals) or 1
    left = 26
    plot_w = width - left
    slot = plot_w / len(series)
    bar = max(min(slot * 0.7, 22), 2)
    drawing.add(Line(left, 16, width, 16, strokeColor=_hex(RULE), strokeWidth=0.6))
    _label(drawing, left - 4, height + 6, f"{peak:,}", 7, MUTED, "end")
    _label(drawing, left - 4, 14, "0", 7, MUTED, "end")
    for i, item in enumerate(series):
        x = left + i * slot + (slot - bar) / 2
        y = 16
        for key, color in keys:
            value = item.get(key, 0)
            if value:
                h = (height - 4) * value / peak
                drawing.add(Rect(x, y, bar, h, fillColor=_hex(color), strokeColor=None))
                y += h
        if i % label_every == 0:
            _label(drawing, x + bar / 2, 5, label_fmt(item), 6.5, MUTED, "middle")
    return drawing


def _timeline_label(item: Dict[str, Any]) -> str:
    moment = datetime.fromisoformat(item["start"])
    return moment.strftime("%H") if item.get("hours", 1) < 24 else moment.strftime("%d/%m")


# --------------------------------------------------------------------------- page furniture


def _styles() -> Dict[str, "ParagraphStyle"]:
    base = dict(fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=_hex(INK), alignment=TA_LEFT)
    return {
        "body": ParagraphStyle("body", **base),
        "small": ParagraphStyle("small", **{**base, "fontSize": 8.2, "leading": 11, "textColor": _hex(MUTED)}),
        "h1": ParagraphStyle("h1", **{**base, "fontName": "Helvetica-Bold", "fontSize": 17, "leading": 21, "spaceAfter": 4}),
        "h2": ParagraphStyle(
            "h2", **{**base, "fontName": "Helvetica-Bold", "fontSize": 12.5, "leading": 16, "spaceBefore": 10, "spaceAfter": 5}
        ),
        "h3": ParagraphStyle("h3", **{**base, "fontName": "Helvetica-Bold", "fontSize": 10.5, "leading": 14}),
        "label": ParagraphStyle(
            "label", **{**base, "fontName": "Helvetica-Bold", "fontSize": 7.5, "leading": 10, "textColor": _hex(MUTED)}
        ),
        "kpi": ParagraphStyle("kpi", **{**base, "fontName": "Helvetica-Bold", "fontSize": 19, "leading": 22}),
        "cell": ParagraphStyle("cell", **{**base, "fontSize": 8.3, "leading": 11}),
    }


def _shield(canvas, x, y, size, fill, stroke=None):
    """The brand mark: a shield with a check."""
    p = canvas.beginPath()
    p.moveTo(x, y + size * 0.95)
    p.lineTo(x + size * 0.45, y + size)
    p.lineTo(x + size * 0.9, y + size * 0.95)
    p.lineTo(x + size * 0.9, y + size * 0.5)
    p.curveTo(x + size * 0.9, y + size * 0.2, x + size * 0.45, y, x + size * 0.45, y)
    p.curveTo(x + size * 0.45, y, x, y + size * 0.2, x, y + size * 0.5)
    p.close()
    canvas.setFillColor(_hex(fill))
    canvas.drawPath(p, fill=1, stroke=0)
    canvas.setStrokeColor(_hex(stroke or NAVY))
    canvas.setLineWidth(size * 0.09)
    canvas.line(x + size * 0.22, y + size * 0.5, x + size * 0.4, y + size * 0.32)
    canvas.line(x + size * 0.4, y + size * 0.32, x + size * 0.7, y + size * 0.68)


class _Report:
    def __init__(self, analysis: Analysis, source_name: str, generated_at: datetime) -> None:
        self.a = analysis
        self.source = safe(source_name, 80)
        self.generated = generated_at
        self.styles = _styles()
        self.data = analysis.to_dict()
        self.page_w, self.page_h = A4
        self.margin = 18 * mm
        self.content_w = self.page_w - 2 * self.margin

    # -- cover and running page decoration

    def draw_cover(self, canvas, doc) -> None:
        w, h = self.page_w, self.page_h
        canvas.saveState()
        canvas.setFillColor(_hex(NAVY))
        canvas.rect(0, h - 6 * mm, w, 6 * mm, fill=1, stroke=0)
        _shield(canvas, self.margin, h - 62 * mm, 16 * mm, NAVY, stroke="#ffffff")
        canvas.setFillColor(_hex(INK))
        canvas.setFont("Helvetica-Bold", 26)
        canvas.drawString(self.margin, h - 82 * mm, "SecLog Sentinel")
        canvas.setFillColor(_hex(ACCENT))
        canvas.setFont("Helvetica", 13)
        canvas.drawString(self.margin, h - 91 * mm, "Security Log Analysis Report")
        canvas.setStrokeColor(_hex(RULE))
        canvas.setLineWidth(0.6)
        canvas.line(self.margin, h - 100 * mm, w - self.margin, h - 100 * mm)

        top = h - 116 * mm
        rows = (
            ("Source log", self.source), ("Analysis date", self.generated.strftime("%d %B %Y, %H:%M")),
            ("Log period", self._period()), ("Result", self._result_line()),
        )
        for i, (label, value) in enumerate(rows):
            y = top - (i // 2) * 17 * mm
            x = self.margin + (i % 2) * 85 * mm
            canvas.setFillColor(_hex(MUTED))
            canvas.setFont("Helvetica-Bold", 8.5)
            canvas.drawString(x, y, label.upper())
            canvas.setFillColor(_hex(INK))
            canvas.setFont("Helvetica", 11)
            canvas.drawString(x, y - 6 * mm, value)

        canvas.setFillColor(_hex(MUTED))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(self.margin, 16 * mm, f"Generated by SecLog Sentinel v{__version__}")
        canvas.drawString(
            self.margin, 11 * mm,
            "Findings are indicators found in a log, not proof of an attack. Verify before acting on them.",
        )
        canvas.restoreState()

    def draw_page(self, canvas, doc) -> None:
        w, h = self.page_w, self.page_h
        canvas.saveState()
        _shield(canvas, self.margin, h - 13 * mm, 6 * mm, NAVY, stroke="#ffffff")
        canvas.setFillColor(_hex(INK))
        canvas.setFont("Helvetica-Bold", 9.5)
        canvas.drawString(self.margin + 8.5 * mm, h - 10.8 * mm, "SecLog Sentinel")
        canvas.setFont("Helvetica", 8.5)
        canvas.setFillColor(_hex(MUTED))
        canvas.drawRightString(w - self.margin, h - 10.8 * mm, self.source)
        canvas.setStrokeColor(_hex(RULE))
        canvas.setLineWidth(0.5)
        canvas.line(self.margin, h - 15 * mm, w - self.margin, h - 15 * mm)
        canvas.line(self.margin, 13 * mm, w - self.margin, 13 * mm)
        canvas.setFillColor(_hex(MUTED))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(self.margin, 8.5 * mm, "Indicators found in a log, not proof of an attack.")
        canvas.drawRightString(w - self.margin, 8.5 * mm, f"Page {doc.page}")
        canvas.restoreState()

    def _period(self) -> str:
        a = self.a
        if not (a.start and a.end):
            return "no events"
        if a.start.date() == a.end.date():
            return f"{a.start:%d %b %Y, %H:%M} to {a.end:%H:%M}"
        return f"{a.start:%d %b %Y %H:%M} to {a.end:%d %b %Y %H:%M}"

    def _result_line(self) -> str:
        counts = self.a.severity_counts()
        total = sum(counts.values())
        if not total:
            return "No findings"
        parts = [f"{counts[n]} {n}" for n in ("critical", "high", "medium", "low") if counts[n]]
        return f"{total} finding{'s' if total != 1 else ''}: " + ", ".join(parts)

    # -- content

    def story(self) -> List[Any]:
        s = self.styles
        out: List[Any] = [NextPageTemplate("page"), PageBreak()]
        out += self.summary_section()
        out += self.charts_section()
        out += self.findings_section()
        out += self.sources_section()
        out += self.appendix_section()
        out.append(Spacer(1, 6))
        out.append(
            Paragraph(
                "Method and limits. SecLog Sentinel applies rule-based detections to SSH log lines. A finding is an "
                "indicator, not confirmation: a user who mistypes a password or an administrator working remotely can "
                "look the same as an attacker. The raw log is not stored by the application.",
                s["small"],
            )
        )
        return out

    def summary_section(self) -> List[Any]:
        s, a = self.styles, self.a
        counts = a.severity_counts()
        failed_pct = f"{a.failed / a.total_events:.0%}" if a.total_events else "n/a"
        headline = (
            "Potential suspicious activity detected." if counts["critical"]
            else "The log shows active attacks." if counts["high"]
            else "The log shows suspicious activity." if sum(counts.values())
            else "No attacks were found in this log."
        )
        tiles = [
            (f"{a.total_events:,}", "Events analyzed"),
            (f"{a.failed:,}", f"Failed logins ({failed_pct})"),
            (f"{a.flagged_total:,}", "Suspicious events"),
            (f"{len(a.findings):,}", "Findings"),
            (f"{a.unique_ips:,}", "Source addresses"),
        ]
        cells = [[Paragraph(value, s["kpi"]) for value, _ in tiles], [Paragraph(label, s["label"]) for _, label in tiles]]
        kpis = Table(cells, colWidths=[self.content_w / 5] * 5)
        kpis.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), _hex("#f2f6fa")),
                    ("LINEAFTER", (0, 0), (-2, -1), 0.6, colors.white),
                    ("TOPPADDING", (0, 0), (-1, 0), 9),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 9),
                    ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ]
            )
        )
        sev_rows = [(n.capitalize(), counts[n], SEVERITY[n]) for n in ("critical", "high", "medium", "low")]
        top = [
            Paragraph("Executive summary", s["h1"]),
            Paragraph(f"<b>{safe(headline)}</b> {safe(self._result_line())} in {a.total_events:,} login events "
                      f"({safe(self._period())}).", s["body"]),
            Spacer(1, 8),
            kpis,
            Paragraph("Findings by severity", s["h2"]),
            bar_chart(sev_rows, self.content_w * 0.62),
        ]
        return top

    def charts_section(self) -> List[Any]:
        s, a = self.styles, self.a
        half = self.content_w / 2 - 6
        types = [
            (item["label"], item["count"], FAILED_COLOR if item["kind"] == "failed" else OK_COLOR)
            for item in a.event_types
        ]
        donut_block = Table(
            [[donut(a.failed, a.accepted), [
                Paragraph("Failed vs successful logins", s["h3"]), Spacer(1, 4),
                Paragraph(f'<font color="{FAILED_COLOR}"><b>{a.failed:,}</b></font> failed', s["body"]),
                Paragraph(f'<font color="{OK_COLOR}"><b>{a.accepted:,}</b></font> accepted', s["body"]),
            ]]],
            colWidths=[130, half - 130],
        )
        donut_block.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        dist = [Paragraph("Security events distribution", s["h3"]), Spacer(1, 4), bar_chart(types, half)]
        row = Table([[donut_block, dist]], colWidths=[half + 6, half + 6])
        row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))

        timeline = a.timeline
        step = max(1, len(timeline) // 16)
        out: List[Any] = [
            Spacer(1, 10), row,
            Paragraph("Activity over time", s["h2"]),
            Paragraph("Failed and accepted logins per interval. The second chart shows the suspicious events "
                      "behind the findings.", s["small"]),
            Spacer(1, 4),
            column_chart(timeline, [("accepted", OK_COLOR), ("failed", FAILED_COLOR)], self.content_w, 90, step, _timeline_label),
            Spacer(1, 6),
            column_chart(timeline, [("suspicious", SUSPICIOUS_COLOR)], self.content_w, 60, step, _timeline_label),
            Paragraph(
                f'<font color="{OK_COLOR}">■</font> accepted &nbsp; <font color="{FAILED_COLOR}">■</font> failed &nbsp; '
                f'<font color="{SUSPICIOUS_COLOR}">■</font> suspicious. Each bar covers '
                f'{(timeline[0]["hours"] if timeline else 1)} hour(s).',
                s["small"],
            ),
        ]
        return out

    def finding_block(self, finding: Dict[str, Any], events: Sequence[Dict[str, Any]]) -> Any:
        s = self.styles
        color = SEVERITY[finding["severity"]]
        chip = Table(
            [[Paragraph(f'<font color="{color}"><b>{safe(finding["severity"]).upper()}</b></font>', s["label"]),
              Paragraph(f'<b>{safe(finding["title"])}</b>', s["h3"])]],
            colWidths=[20 * mm, self.content_w - 20 * mm],
        )
        chip.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), _hex(PANEL)),
                    ("LINEBEFORE", (0, 0), (0, 0), 3, _hex(color)),
                    ("LEFTPADDING", (0, 0), (0, 0), 8),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (0, 0), (0, 0), "LEFT"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        first = datetime.fromisoformat(finding["first_seen"])
        last = datetime.fromisoformat(finding["last_seen"])
        facts = [
            ["Source address", safe(finding["ip"]), "Events", f'{finding["count"]:,}'],
            ["Accounts", safe(", ".join(finding["users"][:6]) + (f' (+{len(finding["users"]) - 6} more)' if len(finding["users"]) > 6 else "")),
             "MITRE ATT&CK", safe(f'{finding["mitre"]["id"]} {finding["mitre"]["name"]}')],
            ["First seen", f"{first:%d %b %Y %H:%M:%S}", "Last seen", f"{last:%d %b %Y %H:%M:%S}"],
        ]
        facts_t = Table(
            [[Paragraph(c, s["label"] if i % 2 == 0 else s["cell"]) for i, c in enumerate(row)] for row in facts],
            colWidths=[26 * mm, self.content_w / 2 - 26 * mm, 26 * mm, self.content_w / 2 - 26 * mm],
        )
        facts_t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2), ("LINEBELOW", (0, 0), (-1, -1), 0.3, _hex(RULE))]))

        parts: List[Any] = [
            chip, Spacer(1, 5),
            Paragraph(f'<b>{safe(finding.get("assessment", "Suspicious indicator"))}.</b> {safe(finding["description"], 700)}', s["body"]),
            Spacer(1, 4), facts_t,
        ]
        evidence = list(events)[:MAX_EVIDENCE_ROWS]
        if evidence:
            rows = [[Paragraph(h, s["label"]) for h in ("TIME", "EVENT", "ACCOUNT", "SOURCE")]]
            for e in evidence:
                rows.append([
                    Paragraph(datetime.fromisoformat(e["time"]).strftime("%d %b %H:%M:%S"), s["cell"]),
                    Paragraph(safe(e["type"]).capitalize(), s["cell"]),
                    Paragraph(safe(e["user"], 40), s["cell"]),
                    Paragraph(safe(e["ip"]), s["cell"]),
                ])
            ev = Table(rows, colWidths=[34 * mm, 34 * mm, 55 * mm, self.content_w - 123 * mm])
            ev.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), _hex("#eaf0f6")), ("LINEBELOW", (0, 1), (-1, -1), 0.25, _hex(RULE)), ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]))
            more = len(events) - len(evidence)
            parts += [Spacer(1, 5), Paragraph("Evidence from the log" + (f" (first {len(evidence)} of {len(events)} events)" if more > 0 else ""), s["label"]), Spacer(1, 2), ev]
        for title, key in (("Why it was flagged", "reason"), ("Why it matters", "impact"), ("Recommended defensive actions", "recommendation")):
            if finding.get(key):
                parts += [Spacer(1, 4), Paragraph(f"<b>{title}.</b> {safe(finding[key], 700)}", s["body"])]
        parts.append(Spacer(1, 14))
        return KeepTogether(parts)

    def findings_section(self) -> List[Any]:
        s = self.styles
        out: List[Any] = [PageBreak(), Paragraph("Security findings", s["h1"])]
        findings = self.data["findings"]
        if not findings:
            out.append(Paragraph("Nothing in this log matched a detection with the thresholds used.", s["body"]))
            return out
        for finding in findings[:MAX_FINDINGS_IN_PDF]:
            out.append(self.finding_block(finding, events_for_finding(finding, self.data["events"])))
        if len(findings) > MAX_FINDINGS_IN_PDF:
            out.append(Paragraph(f"{len(findings) - MAX_FINDINGS_IN_PDF} more findings are in the CSV and JSON exports.", s["small"]))
        return out

    def sources_section(self) -> List[Any]:
        s, a = self.styles, self.a
        if not a.top_sources:
            return []
        rows = [("Source address", "Failed logins", "Accounts tried")]
        rows += [(safe(t["ip"]), f'{t["failures"]:,}', f'{t["distinct_users"]:,}') for t in a.top_sources]
        table = Table(
            [[Paragraph(c, s["label"] if i == 0 else s["cell"]) for c in row] for i, row in enumerate(rows)],
            colWidths=[self.content_w * 0.5, self.content_w * 0.25, self.content_w * 0.25],
        )
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), _hex("#eaf0f6")), ("LINEBELOW", (0, 1), (-1, -1), 0.25, _hex(RULE)), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        chart = bar_chart([(t["ip"], t["failures"], FAILED_COLOR) for t in a.top_sources], self.content_w * 0.8)
        return [KeepTogether([Paragraph("Top source addresses", s["h2"]), chart, Spacer(1, 6), table])]

    def appendix_section(self) -> List[Any]:
        s = self.styles
        events = self.a.flagged_events
        if not events:
            return []
        shown = events[:MAX_APPENDIX_ROWS]
        rows = [[Paragraph(h, s["label"]) for h in ("TIME", "EVENT", "ACCOUNT", "SOURCE", "SEVERITY")]]
        for e in shown:
            rows.append([
                Paragraph(datetime.fromisoformat(e["time"]).strftime("%d %b %H:%M:%S"), s["cell"]),
                Paragraph(safe(e["type"]).capitalize(), s["cell"]),
                Paragraph(safe(e["user"], 40), s["cell"]),
                Paragraph(safe(e["ip"]), s["cell"]),
                Paragraph(f'<font color="{SEVERITY[e["severity"]]}"><b>{safe(e["severity"]).capitalize()}</b></font>', s["cell"]),
            ])
        table = Table(rows, colWidths=[34 * mm, 34 * mm, 48 * mm, 36 * mm, self.content_w - 152 * mm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), _hex("#eaf0f6")), ("LINEBELOW", (0, 1), (-1, -1), 0.25, _hex(RULE)), ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]))
        note = f"First {len(shown)} of {self.a.flagged_total:,} suspicious events. The Events CSV has every stored row." if self.a.flagged_total > len(shown) else f"All {len(shown)} suspicious events."
        return [PageBreak(), Paragraph("Appendix: suspicious events", s["h1"]), Paragraph(note, s["small"]), Spacer(1, 6), table]


def render_pdf(analysis: Analysis, source_name: str = "auth.log", generated_at: Optional[datetime] = None) -> bytes:
    """Return the report as PDF bytes."""
    if not AVAILABLE:
        raise PdfUnavailable("ReportLab is not installed. Run: pip install reportlab")
    report = _Report(analysis, source_name, generated_at or datetime.now())
    buffer = io.BytesIO()
    doc = BaseDocTemplate(
        buffer, pagesize=A4, title="SecLog Sentinel report", author="SecLog Sentinel",
        subject="SSH authentication log analysis", creator=f"SecLog Sentinel v{__version__}",
        leftMargin=report.margin, rightMargin=report.margin, topMargin=22 * mm, bottomMargin=20 * mm,
    )
    cover = Frame(0, 0, 1, 1, id="cover", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    body = Frame(report.margin, 20 * mm, report.content_w, report.page_h - 42 * mm, id="body", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates(
        [
            PageTemplate(id="cover", frames=[cover], onPage=report.draw_cover),
            PageTemplate(id="page", frames=[body], onPage=report.draw_page),
        ]
    )
    doc.build(report.story())
    return buffer.getvalue()
