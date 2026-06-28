"""HTML report writer.

Produces a self-contained, dependency-free HTML report. All CSS, SVG charts and
JavaScript are inlined, so the file works fully offline and inside sandboxed
preview iframes (``sandbox="allow-scripts"``) — no external scripts, fonts, CSS
or CDNs are required.

UX features
-----------
* Executive summary with a verdict banner + animated risk-score gauge.
* KPI stat cards with risk-aware accent colors.
* Interactive bar chart (IOC types) and donut chart (risk distribution).
* Live search box that filters every indicator row instantly.
* Risk filter chips, per-column sorting and one-click copy for any indicator.
* Light / dark theme toggle (persists for the session).
* Sticky table headers, type icons, keyboard focus styles and a print stylesheet.
"""
from __future__ import annotations

import html
import json
import math
from typing import Dict, List

from iocforge.core.models import AnalysisReport, Indicator, IOCType, RiskLevel
from iocforge.reporting.base import BaseReporter

# Inline SVG glyphs (currentColor) used as IOC-type icons in the UI.
_TYPE_ICONS: Dict[IOCType, str] = {
    IOCType.IPV4: "🌐",
    IOCType.IPV6: "🌐",
    IOCType.DOMAIN: "🔗",
    IOCType.URL: "🧭",
    IOCType.EMAIL: "✉️",
    IOCType.MD5: "🔑",
    IOCType.SHA1: "🔑",
    IOCType.SHA256: "🔑",
    IOCType.BITCOIN: "₿",
    IOCType.CVE: "🐞",
    IOCType.MITRE: "🎯",
}


class HTMLReporter(BaseReporter):
    """Render a styled, interactive, chart-rich HTML report."""

    extension = ".html"

    # --- Public ------------------------------------------------------------
    def render(self, report: AnalysisReport) -> str:
        verdict = self._verdict(report)
        return _TEMPLATE.format(
            generated=html.escape(report.generated_at),
            version=html.escape(report.tool_version or ""),
            sources=html.escape(", ".join(report.source_files) or "—"),
            source_count=len(report.source_files),
            verdict_banner=verdict["banner"],
            gauge=self._risk_gauge(report),
            stat_cards=self._stat_cards(report),
            type_chart=self._bar_chart(report.counts_by_type(), "IOCs by Type"),
            risk_chart=self._risk_donut(report.counts_by_risk()),
            risk_chips=self._risk_chips(report),
            ti_section=self._threat_intel_section(report),
            ioc_tables=self._ioc_tables(report),
            total=report.total_iocs,
        )

    # --- Executive verdict -------------------------------------------------
    def _verdict(self, report: AnalysisReport) -> Dict[str, str]:
        by_risk = report.counts_by_risk()
        critical = by_risk.get("critical", 0)
        high = by_risk.get("high", 0)
        medium = by_risk.get("medium", 0)
        flagged = len(report.malicious_indicators())

        if critical or high:
            level, title = RiskLevel.CRITICAL if critical else RiskLevel.HIGH, "Action Required"
            msg = (
                f"{flagged} indicator(s) were flagged as malicious "
                f"({critical} critical, {high} high). Investigate immediately."
            )
        elif medium:
            level, title = RiskLevel.MEDIUM, "Review Recommended"
            msg = f"{medium} indicator(s) rated medium risk warrant a closer look."
        elif report.total_iocs:
            level, title = RiskLevel.CLEAN, "No Threats Detected"
            msg = (
                "No indicators were flagged as malicious by the configured "
                "Threat Intelligence providers."
            )
        else:
            level, title = RiskLevel.UNKNOWN, "No Indicators Found"
            msg = "No indicators of compromise were extracted from the input."

        banner = (
            f'<div class="verdict" style="--accent:{level.color}">'
            f'<div class="verdict-icon">{self._verdict_icon(level)}</div>'
            f'<div class="verdict-text"><h2>{html.escape(title)}</h2>'
            f"<p>{html.escape(msg)}</p></div>"
            f'<div class="verdict-pill" style="background:{level.color}">'
            f"{html.escape(level.value.upper())}</div></div>"
        )
        return {"banner": banner}

    @staticmethod
    def _verdict_icon(level: RiskLevel) -> str:
        if level.rank >= RiskLevel.HIGH.rank:
            return "⚠️"
        if level is RiskLevel.MEDIUM:
            return "🔎"
        if level is RiskLevel.CLEAN:
            return "✅"
        return "ℹ️"

    # --- Risk score gauge --------------------------------------------------
    def _risk_score(self, report: AnalysisReport) -> int:
        """Weighted 0–100 risk score across all enriched indicators."""
        weights = {
            RiskLevel.CRITICAL: 100,
            RiskLevel.HIGH: 75,
            RiskLevel.MEDIUM: 45,
            RiskLevel.LOW: 20,
            RiskLevel.CLEAN: 0,
            RiskLevel.UNKNOWN: 0,
        }
        scored = [
            weights[i.risk_level]
            for i in report.all_indicators()
            if i.risk_level not in (RiskLevel.UNKNOWN,)
        ]
        if not scored:
            return 0
        # Bias towards the worst finding so a single critical isn't diluted.
        return int(round(0.6 * max(scored) + 0.4 * (sum(scored) / len(scored))))

    def _risk_gauge(self, report: AnalysisReport) -> str:
        score = self._risk_score(report)
        if score >= 80:
            color, label = RiskLevel.CRITICAL.color, "Critical"
        elif score >= 60:
            color, label = RiskLevel.HIGH.color, "High"
        elif score >= 35:
            color, label = RiskLevel.MEDIUM.color, "Medium"
        elif score > 0:
            color, label = RiskLevel.LOW.color, "Low"
        else:
            color, label = RiskLevel.CLEAN.color, "Clean"

        r = 70
        circ = 2 * math.pi * r
        # Semi-circle gauge: only the top half (180°) is used.
        arc = circ / 2
        filled = (score / 100) * arc
        return (
            '<svg viewBox="0 0 180 110" class="gauge" role="img" '
            f'aria-label="Risk score {score} of 100">'
            f'<path d="M20,100 A70,70 0 0 1 160,100" fill="none" '
            'stroke="var(--track)" stroke-width="16" stroke-linecap="round"/>'
            f'<path d="M20,100 A70,70 0 0 1 160,100" fill="none" '
            f'stroke="{color}" stroke-width="16" stroke-linecap="round" '
            f'stroke-dasharray="{filled:.1f} {arc:.1f}" class="gauge-fill"/>'
            f'<text x="90" y="84" class="gauge-score">{score}</text>'
            f'<text x="90" y="102" class="gauge-label" fill="{color}">'
            f"{html.escape(label)}</text></svg>"
        )

    # --- KPI cards ---------------------------------------------------------
    def _stat_cards(self, report: AnalysisReport) -> str:
        by_risk = report.counts_by_risk()
        cards = [
            ("Total IOCs", report.total_iocs, "#38bdf8", "🧬"),
            ("IOC Types", len(report.counts_by_type()), "#a78bfa", "🗂️"),
            ("Flagged (Med+)", len(report.malicious_indicators()), "#fb923c", "🚩"),
            ("Critical", by_risk.get("critical", 0), RiskLevel.CRITICAL.color, "⛔"),
        ]
        return "".join(
            f'<div class="card" style="--accent:{color}">'
            f'<div class="card-top"><span class="card-icon">{icon}</span>'
            f'<span class="card-label">{html.escape(label)}</span></div>'
            f'<div class="card-value">{value}</div></div>'
            for label, value, color, icon in cards
        )

    # --- Charts ------------------------------------------------------------
    def _bar_chart(self, data: Dict[str, int], title: str) -> str:
        if not data:
            return "<div class='chart-empty'>No data available</div>"
        items = sorted(data.items(), key=lambda x: -x[1])
        max_val = max(v for _, v in items) or 1
        bar_h, gap, label_w = 24, 14, 120
        width = 520
        height = len(items) * (bar_h + gap) + 8
        rows: List[str] = []
        for idx, (label, value) in enumerate(items):
            y = idx * (bar_h + gap) + 4
            bar_w = max(2, int((value / max_val) * (width - label_w - 70)))
            rows.append(
                f'<text x="0" y="{y + bar_h - 7}" class="bar-label">'
                f"{html.escape(label)}</text>"
                f'<rect x="{label_w}" y="{y}" width="0" height="{bar_h}" rx="5" '
                f'fill="url(#barGrad)" class="bar"><animate attributeName="width" '
                f'from="0" to="{bar_w}" dur="0.7s" fill="freeze" '
                f'calcMode="spline" keySplines="0.2 0.8 0.2 1"/></rect>'
                f'<text x="{label_w + bar_w + 8}" y="{y + bar_h - 7}" '
                f'class="bar-value">{value}</text>'
            )
        return (
            f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" '
            f'aria-label="{html.escape(title)}">'
            '<defs><linearGradient id="barGrad" x1="0" y1="0" x2="1" y2="0">'
            '<stop offset="0" stop-color="#38bdf8"/>'
            '<stop offset="1" stop-color="#6366f1"/></linearGradient></defs>'
            + "".join(rows)
            + "</svg>"
        )

    def _risk_donut(self, by_risk: Dict[str, int]) -> str:
        total = sum(by_risk.values())
        if total == 0:
            return "<div class='chart-empty'>No risk data</div>"
        cx, cy, r, stroke = 90, 90, 62, 26
        circumference = 2 * math.pi * r
        offset = 0.0
        segments: List[str] = []
        legend: List[str] = []
        order = ["critical", "high", "medium", "low", "clean", "unknown"]
        for key in order:
            value = by_risk.get(key, 0)
            if not value:
                continue
            fraction = value / total
            color = RiskLevel(key).color
            dash = fraction * circumference
            segments.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="{color}" stroke-width="{stroke}" '
                f'stroke-dasharray="{dash:.2f} {circumference - dash:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" stroke-linecap="butt" '
                f'transform="rotate(-90 {cx} {cy})" class="donut-seg">'
                f"<title>{key.title()}: {value}</title></circle>"
            )
            offset += dash
            pct = round(fraction * 100)
            legend.append(
                f'<li><span class="dot" style="background:{color}"></span>'
                f'<span class="leg-label">{html.escape(key.title())}</span>'
                f'<span class="leg-val">{value} · {pct}%</span></li>'
            )
        svg = (
            '<svg viewBox="0 0 180 180" width="170" height="170" '
            'class="donut" role="img" aria-label="Risk distribution">'
            + "".join(segments)
            + f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" '
            f'class="donut-center">{total}</text>'
            f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" '
            'class="donut-sub">IOCs</text></svg>'
        )
        return f'<div class="donut-wrap">{svg}<ul class="legend">{"".join(legend)}</ul></div>'

    def _risk_chips(self, report: AnalysisReport) -> str:
        by_risk = report.counts_by_risk()
        order = ["critical", "high", "medium", "low", "clean", "unknown"]
        chips = [
            '<button class="chip is-active" data-risk="all" '
            'onclick="filterRisk(this)">All</button>'
        ]
        for key in order:
            count = by_risk.get(key, 0)
            if not count:
                continue
            color = RiskLevel(key).color
            chips.append(
                f'<button class="chip" data-risk="{key}" '
                f'onclick="filterRisk(this)" style="--chip:{color}">'
                f'<span class="chip-dot" style="background:{color}"></span>'
                f"{key.title()} <b>{count}</b></button>"
            )
        return "".join(chips)

    # --- Tables ------------------------------------------------------------
    def _ioc_tables(self, report: AnalysisReport) -> str:
        sections: List[str] = []
        for ioc_type in IOCType:
            items = report.indicators.get(ioc_type)
            if not items:
                continue
            sections.append(self._single_table(ioc_type, items))
        if not sections:
            return (
                '<div class="empty-state">🗂️<p>No indicators were extracted.</p>'
                "</div>"
            )
        return "".join(sections)

    def _single_table(self, ioc_type: IOCType, items: List[Indicator]) -> str:
        icon = _TYPE_ICONS.get(ioc_type, "•")
        rows: List[str] = []
        for ioc in items:
            risk = ioc.risk_level
            summary = next((e.summary for e in ioc.enrichment if e.summary), "")
            value_esc = html.escape(ioc.value)
            value_attr = html.escape(json.dumps(ioc.value))
            badge = (
                f'<span class="badge" style="background:{risk.color}">'
                f"{html.escape(risk.value)}</span>"
            )
            rows.append(
                f'<tr data-risk="{risk.value}" '
                f'data-search="{html.escape(ioc.value.lower())}">'
                f'<td class="mono"><span class="ioc-val">{value_esc}</span>'
                f'<button class="copy" title="Copy" '
                f"onclick='copyVal(this,{value_attr})'>⧉</button></td>"
                f'<td class="num">{ioc.count}</td>'
                f'<td data-rank="{risk.rank}">{badge}</td>'
                f"<td>{html.escape(summary)}</td></tr>"
            )
        return (
            '<section class="table-card">'
            f'<header class="table-head" onclick="toggleCard(this)">'
            f'<span class="t-icon">{icon}</span>'
            f"<h3>{html.escape(ioc_type.label)}</h3>"
            f'<span class="count-pill">{len(items)}</span>'
            '<span class="chevron">▾</span></header>'
            '<div class="table-body"><table class="ioc-table">'
            "<thead><tr>"
            '<th onclick="sortTable(this,0,\'str\')">Indicator <i>⇅</i></th>'
            '<th class="num" onclick="sortTable(this,1,\'num\')">Count <i>⇅</i></th>'
            '<th onclick="sortTable(this,2,\'rank\')">Risk <i>⇅</i></th>'
            "<th>Notes</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div></section>"
        )

    def _threat_intel_section(self, report: AnalysisReport) -> str:
        malicious = report.malicious_indicators()
        if not malicious:
            return (
                '<div class="empty-state ok">✅'
                "<p>No indicators were flagged as malicious by the configured "
                "Threat Intelligence providers.</p></div>"
            )
        rows: List[str] = []
        for ioc in malicious:
            providers = ", ".join(
                f"{e.provider} ({e.risk_level.value})"
                for e in ioc.enrichment
                if e.risk_level is not RiskLevel.UNKNOWN
            )
            value_attr = html.escape(json.dumps(ioc.value))
            rows.append(
                "<tr>"
                f'<td class="mono"><span class="ioc-val">{html.escape(ioc.value)}'
                f'</span><button class="copy" title="Copy" '
                f"onclick='copyVal(this,{value_attr})'>⧉</button></td>"
                f"<td>{html.escape(ioc.ioc_type.label)}</td>"
                f'<td><span class="badge" style="background:{ioc.risk_level.color}">'
                f"{ioc.risk_level.value}</span></td>"
                f"<td>{html.escape(providers)}</td></tr>"
            )
        return (
            '<table class="ioc-table"><thead><tr><th>Indicator</th><th>Type</th>'
            "<th>Risk</th><th>Providers</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )


_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IOCForge Report</title>
<style>
  :root {{
    --bg:#0b0f17; --bg2:#0f1522; --panel:#151d2c;
    --panel-2:#1b2436; --line:#243044; --text:#e6edf3; --muted:#93a1b3;
    --accent:#2dd4bf; --track:#22304a; --shadow:0 8px 30px rgba(0,0,0,.35);
    --radius:14px;
  }}
  html[data-theme="light"] {{
    --bg:#eef2f7; --bg2:#e3e9f2; --panel:#ffffff; --panel-2:#f3f6fb;
    --line:#dce3ec; --text:#10202f; --muted:#5c6b7d; --track:#dde6f1;
    --shadow:0 8px 24px rgba(31,45,61,.10);
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:radial-gradient(1200px 600px at 80% -10%,
          rgba(45,212,191,.08),transparent), var(--bg);
          color:var(--text); font-family:'Segoe UI',-apple-system,
          BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;
          line-height:1.5; -webkit-font-smoothing:antialiased; }}

  header.top {{ position:sticky; top:0; z-index:20;
    background:linear-gradient(135deg, rgba(17,21,28,.92), rgba(31,43,58,.92));
    backdrop-filter:blur(8px); border-bottom:1px solid var(--line);
    padding:16px 28px; display:flex; align-items:center; gap:16px; }}
  html[data-theme="light"] header.top {{
    background:linear-gradient(135deg, rgba(255,255,255,.94), rgba(243,246,251,.94)); }}
  .brand {{ display:flex; flex-direction:column; }}
  .brand h1 {{ margin:0; font-size:22px; letter-spacing:.5px;
    background:linear-gradient(90deg,#2dd4bf,#6366f1);
    -webkit-background-clip:text; background-clip:text;
    -webkit-text-fill-color:transparent; }}
  .brand .tag {{ color:var(--muted); font-size:11px; letter-spacing:2.5px; }}
  .spacer {{ flex:1; }}
  .meta-mini {{ color:var(--muted); font-size:12px; text-align:right;
    max-width:42ch; overflow:hidden; text-overflow:ellipsis; }}
  .theme-btn {{ cursor:pointer; border:1px solid var(--line);
    background:var(--panel); color:var(--text); border-radius:10px;
    padding:8px 12px; font-size:14px; }}
  .theme-btn:hover {{ border-color:var(--accent); }}

  main {{ padding:24px; max-width:1180px; margin:0 auto; }}

  .verdict {{ display:flex; align-items:center; gap:18px; padding:20px 24px;
    border-radius:var(--radius); background:var(--panel);
    border:1px solid var(--line); border-left:6px solid var(--accent);
    box-shadow:var(--shadow); margin-bottom:22px; }}
  .verdict-icon {{ font-size:34px; }}
  .verdict-text h2 {{ margin:0 0 2px; font-size:19px; }}
  .verdict-text p {{ margin:0; color:var(--muted); font-size:13.5px; }}
  .verdict-pill {{ margin-left:auto; color:#fff; font-weight:700;
    padding:6px 14px; border-radius:30px; font-size:12px; letter-spacing:1px; }}

  .hero {{ display:grid; grid-template-columns:220px 1fr; gap:20px;
    margin-bottom:22px; }}
  @media (max-width:820px) {{ .hero {{ grid-template-columns:1fr; }} }}
  .gauge-card {{ background:var(--panel); border:1px solid var(--line);
    border-radius:var(--radius); box-shadow:var(--shadow);
    display:flex; flex-direction:column; align-items:center;
    justify-content:center; padding:18px; }}
  .gauge {{ width:180px; }}
  .gauge-score {{ fill:var(--text); font-size:34px; font-weight:800;
    text-anchor:middle; }}
  .gauge-label {{ font-size:13px; font-weight:700; text-anchor:middle;
    text-transform:uppercase; letter-spacing:1px; }}
  .gauge-cap {{ color:var(--muted); font-size:11px; margin-top:4px;
    letter-spacing:1px; text-transform:uppercase; }}

  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
    gap:14px; }}
  .card {{ background:var(--panel); border:1px solid var(--line);
    border-radius:var(--radius); padding:16px 18px; box-shadow:var(--shadow);
    position:relative; overflow:hidden; transition:transform .15s ease; }}
  .card:hover {{ transform:translateY(-3px); }}
  .card::after {{ content:""; position:absolute; left:0; top:0; bottom:0;
    width:4px; background:var(--accent); }}
  .card-top {{ display:flex; align-items:center; gap:8px; color:var(--muted);
    font-size:12.5px; }}
  .card-icon {{ font-size:15px; }}
  .card-value {{ font-size:30px; font-weight:800; margin-top:6px;
    color:var(--accent); }}

  .grid2 {{ display:grid; grid-template-columns:1.15fr .85fr; gap:20px;
    margin:22px 0; }}
  @media (max-width:820px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
  .panel {{ background:var(--panel); border:1px solid var(--line);
    border-radius:var(--radius); padding:20px 22px; box-shadow:var(--shadow); }}
  .panel h2, .section-title {{ font-size:15px; margin:0 0 14px;
    display:flex; align-items:center; gap:8px; letter-spacing:.3px; }}
  .panel h2::before {{ content:""; width:4px; height:16px; border-radius:3px;
    background:var(--accent); display:inline-block; }}
  .section-title {{ margin:28px 0 14px; font-size:16px; }}

  .bar-label {{ fill:var(--muted); font-size:12px; }}
  .bar-value {{ fill:var(--text); font-size:12px; font-weight:600; }}
  .donut-wrap {{ display:flex; align-items:center; gap:22px; flex-wrap:wrap;
    justify-content:center; }}
  .donut-seg {{ transition:opacity .2s; cursor:default; }}
  .donut-seg:hover {{ opacity:.78; }}
  .donut-center {{ fill:var(--text); font-size:30px; font-weight:800; }}
  .donut-sub {{ fill:var(--muted); font-size:11px; letter-spacing:1px; }}
  .legend {{ list-style:none; padding:0; margin:0; font-size:13px; min-width:150px; }}
  .legend li {{ display:flex; align-items:center; gap:8px; margin:7px 0; }}
  .leg-label {{ flex:1; }}
  .leg-val {{ color:var(--muted); font-variant-numeric:tabular-nums; }}
  .dot {{ width:11px; height:11px; border-radius:50%; flex-shrink:0; }}

  .toolbar {{ display:flex; gap:12px; flex-wrap:wrap; align-items:center;
    margin:6px 0 18px; }}
  .search {{ flex:1; min-width:220px; display:flex; align-items:center;
    gap:8px; background:var(--panel); border:1px solid var(--line);
    border-radius:10px; padding:9px 14px; }}
  .search:focus-within {{ border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(45,212,191,.15); }}
  .search input {{ flex:1; background:transparent; border:0; outline:0;
    color:var(--text); font-size:14px; }}
  .search input::placeholder {{ color:var(--muted); }}
  .chips {{ display:flex; gap:8px; flex-wrap:wrap; }}
  .chip {{ cursor:pointer; border:1px solid var(--line); background:var(--panel);
    color:var(--text); border-radius:30px; padding:7px 13px; font-size:12.5px;
    display:flex; align-items:center; gap:6px; transition:all .15s; }}
  .chip:hover {{ border-color:var(--chip,var(--accent)); }}
  .chip.is-active {{ background:var(--chip,var(--accent)); color:#06121a;
    border-color:transparent; font-weight:700; }}
  .chip.is-active .chip-dot {{ display:none; }}
  .chip-dot {{ width:9px; height:9px; border-radius:50%; }}
  .chip b {{ font-variant-numeric:tabular-nums; }}

  .table-card {{ background:var(--panel); border:1px solid var(--line);
    border-radius:var(--radius); margin-bottom:14px; overflow:hidden;
    box-shadow:var(--shadow); }}
  .table-head {{ display:flex; align-items:center; gap:10px; padding:14px 18px;
    cursor:pointer; user-select:none; }}
  .table-head:hover {{ background:var(--panel-2); }}
  .table-head h3 {{ margin:0; font-size:14.5px; }}
  .t-icon {{ font-size:16px; }}
  .count-pill {{ background:var(--panel-2); border:1px solid var(--line);
    color:var(--muted); border-radius:20px; padding:1px 10px; font-size:12px;
    font-weight:600; }}
  .chevron {{ margin-left:auto; color:var(--muted); transition:transform .2s; }}
  .table-card.collapsed .chevron {{ transform:rotate(-90deg); }}
  .table-card.collapsed .table-body {{ display:none; }}
  .table-body {{ overflow-x:auto; }}

  table.ioc-table {{ width:100%; border-collapse:collapse; }}
  .ioc-table thead th {{ position:sticky; top:0; background:var(--panel-2);
    text-align:left; padding:10px 14px; font-size:11px; letter-spacing:.6px;
    text-transform:uppercase; color:var(--muted); cursor:pointer;
    border-bottom:1px solid var(--line); white-space:nowrap; }}
  .ioc-table thead th i {{ opacity:.4; font-style:normal; font-size:10px; }}
  .ioc-table thead th:hover i {{ opacity:.9; }}
  .ioc-table td {{ padding:9px 14px; border-bottom:1px solid var(--line);
    font-size:13px; vertical-align:top; }}
  .ioc-table tbody tr:hover {{ background:var(--panel-2); }}
  .ioc-table tbody tr.hidden {{ display:none; }}
  .num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .mono {{ font-family:'SF Mono',Consolas,Menlo,monospace; word-break:break-all; }}
  .ioc-val {{ }}
  .copy {{ margin-left:6px; border:0; background:transparent; cursor:pointer;
    color:var(--muted); font-size:14px; opacity:0; transition:opacity .15s; }}
  tr:hover .copy {{ opacity:1; }}
  .copy:hover {{ color:var(--accent); }}
  .copy.done {{ color:#2ecc71; opacity:1; }}
  .badge {{ color:#fff; padding:3px 11px; border-radius:20px; font-size:10.5px;
    text-transform:uppercase; font-weight:700; letter-spacing:.4px;
    display:inline-block; }}

  .empty-state {{ text-align:center; color:var(--muted); padding:34px 16px;
    font-size:15px; }}
  .empty-state.ok {{ color:#2ecc71; }}
  .empty-state p {{ margin:10px 0 0; }}
  .no-results {{ text-align:center; color:var(--muted); padding:24px;
    display:none; }}

  footer {{ text-align:center; color:var(--muted); font-size:12px;
    padding:30px 16px; border-top:1px solid var(--line); margin-top:24px; }}
  footer b {{ color:var(--accent); }}

  ::selection {{ background:rgba(45,212,191,.3); }}
  :focus-visible {{ outline:2px solid var(--accent); outline-offset:2px; }}

  @media print {{
    header.top {{ position:static; }}
    .toolbar, .theme-btn, .copy {{ display:none !important; }}
    .table-card.collapsed .table-body {{ display:block !important; }}
    body {{ background:#fff; color:#000; }}
  }}
</style>
</head>
<body>
<header class="top">
  <div class="brand">
    <h1>🛡 IOCForge</h1>
    <span class="tag">EXTRACT • ANALYZE • ENRICH • UNDERSTAND</span>
  </div>
  <div class="spacer"></div>
  <div class="meta-mini">
    <div>Generated {generated}</div>
    <div>v{version} · {source_count} source(s)</div>
  </div>
  <button class="theme-btn" onclick="toggleTheme()" title="Toggle theme"
    aria-label="Toggle light/dark theme"><span id="themeIcon">☀️</span></button>
</header>

<main>
  {verdict_banner}

  <div class="hero">
    <div class="gauge-card">
      {gauge}
      <div class="gauge-cap">Risk Score</div>
    </div>
    <div class="cards">{stat_cards}</div>
  </div>

  <div class="grid2">
    <div class="panel"><h2>IOCs by Type</h2>{type_chart}</div>
    <div class="panel"><h2>Risk Distribution</h2>{risk_chart}</div>
  </div>

  <div class="panel">
    <h2>Threat Intelligence — Flagged Indicators</h2>
    {ti_section}
  </div>

  <h2 class="section-title">🔍 All Extracted Indicators <span
    style="color:var(--muted);font-weight:400;font-size:13px">({total})</span></h2>

  <div class="toolbar">
    <label class="search">🔎
      <input id="q" type="search" placeholder="Search indicators…"
        oninput="searchIOCs(this.value)" aria-label="Search indicators">
    </label>
    <div class="chips">{risk_chips}</div>
  </div>

  <div id="tables">{ioc_tables}</div>
  <div class="no-results" id="noResults">No indicators match your filters.</div>
</main>

<footer>Report produced by <b>IOCForge</b> — for authorized security research only.</footer>

<script>
/* ---- Theme toggle ---- */
function toggleTheme() {{
  var root = document.documentElement;
  var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  document.getElementById('themeIcon').textContent = next === 'dark' ? '☀️' : '🌙';
}}

/* ---- Collapse / expand a table card ---- */
function toggleCard(head) {{ head.parentElement.classList.toggle('collapsed'); }}

/* ---- Copy an indicator value ---- */
function copyVal(btn, val) {{
  var done = function() {{ var t = btn.textContent; btn.textContent='✓';
    btn.classList.add('done');
    setTimeout(function(){{ btn.textContent=t; btn.classList.remove('done'); }}, 1100); }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(val).then(done, function(){{ fallbackCopy(val); done(); }});
  }} else {{ fallbackCopy(val); done(); }}
}}
function fallbackCopy(val) {{
  var ta = document.createElement('textarea'); ta.value = val;
  ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta);
  ta.select(); try {{ document.execCommand('copy'); }} catch(e) {{}}
  document.body.removeChild(ta);
}}

/* ---- State + combined search/risk filtering ---- */
var activeRisk = 'all';
var query = '';
function applyFilters() {{
  var anyVisible = false;
  document.querySelectorAll('.table-card').forEach(function(card) {{
    var shownInCard = 0;
    card.querySelectorAll('tbody tr').forEach(function(tr) {{
      var matchRisk = activeRisk === 'all' || tr.getAttribute('data-risk') === activeRisk;
      var matchText = !query || (tr.getAttribute('data-search') || '').indexOf(query) !== -1;
      var show = matchRisk && matchText;
      tr.classList.toggle('hidden', !show);
      if (show) {{ shownInCard++; anyVisible = true; }}
    }});
    /* Hide whole card when it has no matching rows */
    card.style.display = shownInCard === 0 ? 'none' : '';
  }});
  document.getElementById('noResults').style.display = anyVisible ? 'none' : 'block';
}}
function searchIOCs(v) {{ query = (v || '').trim().toLowerCase(); applyFilters(); }}
function filterRisk(btn) {{
  document.querySelectorAll('.chip').forEach(function(c){{ c.classList.remove('is-active'); }});
  btn.classList.add('is-active');
  activeRisk = btn.getAttribute('data-risk');
  applyFilters();
}}

/* ---- Column sorting ---- */
function sortTable(th, col, type) {{
  var table = th.closest('table');
  var tbody = table.querySelector('tbody');
  var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
  var dir = th.getAttribute('data-dir') === 'asc' ? -1 : 1;
  th.setAttribute('data-dir', dir === 1 ? 'asc' : 'desc');
  rows.sort(function(a, b) {{
    var x, y;
    if (type === 'num') {{
      x = parseFloat(a.cells[col].textContent) || 0;
      y = parseFloat(b.cells[col].textContent) || 0;
      return (x - y) * dir;
    }} else if (type === 'rank') {{
      x = parseInt(a.cells[col].getAttribute('data-rank')) || 0;
      y = parseInt(b.cells[col].getAttribute('data-rank')) || 0;
      return (x - y) * dir;
    }}
    x = a.cells[col].textContent.toLowerCase();
    y = b.cells[col].textContent.toLowerCase();
    return x < y ? -dir : x > y ? dir : 0;
  }});
  rows.forEach(function(r) {{ tbody.appendChild(r); }});
}}
</script>
</body>
</html>"""
