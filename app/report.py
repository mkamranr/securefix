"""Excel report of one analysis: a summary sheet and one row per finding, with links back to GitLab."""
import re
from datetime import datetime, timezone
from io import BytesIO

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

from .analyzer import SEVERITIES
from .prompts import fix_mr, posted_note, vulnerability_url

MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
MAX_CELL = 32767  # Excel's limit per cell

VERDICTS = {"true_positive": "Real", "needs_review": "Needs review", "false_positive": "False positive"}
STATUSES = {"pending": "Waiting", "analyzing": "Analyzing", "done": "Analyzed", "error": "Error", "skipped": "Skipped"}
VALIDATION = {"passed": "Passed", "failed": "Failed", "not_configured": "Not validated", "skipped": "Skipped"}

NAVY, INK, MUTED, LINE, BAND = "1F2A44", "1B2433", "5B6678", "D5DAE3", "F3F5F9"
# (fill, font) per value
SEV_STYLE = {"critical": ("7A0E14", "FFFFFF"), "high": ("D93A3A", "FFFFFF"), "medium": ("F08A24", "FFFFFF"),
             "low": ("F6D04D", INK), "info": ("C9D3E0", INK), "unknown": ("E2E6EC", INK)}
VERDICT_STYLE = {"Real": ("FDE2E1", "A3201A"), "Needs review": ("FFF1CC", "8A5A00"),
                 "False positive": ("DDF3E4", "1D6B3A"), "Skipped": ("EEF0F4", MUTED), "Error": ("FDE2E1", "A3201A"),
                 "Waiting": ("EEF0F4", MUTED), "Analyzing": ("E3ECFB", "1F4E9C")}
YES_NO_STYLE = {"Yes": ("DDF3E4", "1D6B3A"), "No": ("EEF0F4", MUTED)}

THIN = Side(style="thin", color=LINE)
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
HEAD_FONT = Font(name="Calibri", bold=True, color="FFFFFF", size=11)
HEAD_FILL = PatternFill("solid", fgColor=NAVY)
LINK_FONT = Font(name="Calibri", color="1F5FBF", underline="single")
BODY_FONT = Font(name="Calibri", color=INK, size=10.5)
TOP = Alignment(vertical="top")
WRAP = Alignment(vertical="top", wrap_text=True)
CENTER = Alignment(vertical="top", horizontal="center")

# (header, width, alignment)
COLUMNS = [
    ("#", 6, CENTER), ("Severity", 11, CENTER), ("Verdict", 15, CENTER), ("Confidence", 11, CENTER),
    ("Finding", 46, WRAP), ("CWE", 11, TOP), ("Location", 38, WRAP), ("GitLab issue", 13, CENTER),
    ("Link", 24, TOP), ("Analysis posted", 15, CENTER), ("Posted by", 14, TOP), ("Posted at", 17, TOP),
    ("Fix proposed", 13, CENTER), ("Fix validation", 15, TOP), ("Fix MR", 10, CENTER), ("Dismissed", 11, CENTER),
    ("Copied from", 13, CENTER), ("Scanner", 18, TOP), ("Status", 11, TOP), ("Analysis time (s)", 12, CENTER),
    ("Tokens generated", 12, CENTER), ("Reasoning", 80, WRAP), ("Error", 40, WRAP),
]


def _text(value) -> str:
    return ILLEGAL_CHARACTERS_RE.sub("", str(value))[:MAX_CELL]


def _put(ws, row: int, col: int, value=None, *, link: str | None = None, style=None, font=None, fill=None,
         align=None, fmt: str | None = None):
    """Writes a cell. Text is always stored as text, so scanner or model output starting with = is never a formula."""
    cell = ws.cell(row=row, column=col)
    if isinstance(value, str):
        cell.value = _text(value)
        cell.data_type = "s"
    else:
        cell.value = value
    if fmt:
        cell.number_format = fmt
    cell.font = font or (LINK_FONT if link else BODY_FONT)
    if link and re.match(r"https?://", link):
        cell.hyperlink = link
    if style:
        bg, fg = style
        cell.fill = PatternFill("solid", fgColor=bg)
        cell.font = Font(name="Calibri", bold=True, color=fg, size=10.5)
    elif fill:
        cell.fill = fill
    cell.alignment = align or TOP
    return cell


def _when(value) -> str:
    if not value:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value[:16]
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _duration(findings) -> str:
    """Total and average time of the findings the model analyzed (copied ones took no model time)."""
    times = [f.duration_s for f in findings if f.status == "done" and not f.copied_from and f.duration_s is not None]
    if not times:
        return "No findings were analyzed by the model"
    total = sum(times)
    return f"{total / 60:.1f} min in total, {total / len(times):.1f} s per analyzed finding ({len(times)})"


def _verdict(f) -> str:
    return VERDICTS.get(f.verdict, "Unknown") if f.status == "done" else STATUSES.get(f.status, f.status)


def _action(f, prefix: str) -> dict | None:
    return next((a for a in f.actions or [] if str(a.get("type", "")).startswith(prefix)), None)


def _location(f) -> str:
    if not f.start_line:
        return f.file
    end = f"-{f.end_line}" if f.end_line and f.end_line != f.start_line else ""
    return f"{f.file}:{f.start_line}{end}"


def _blob_url(f, job, gitlab_url: str) -> str:
    lines = f"#L{f.start_line}" + (f"-{f.end_line}" if f.end_line and f.end_line != f.start_line else "") if f.start_line else ""
    return f"{gitlab_url}/{job.project_path}/-/blob/{job.sha}/{f.file}{lines}"


def _sorted(findings):
    sev = {s: i for i, s in enumerate(SEVERITIES)}
    order = {v: i for i, v in enumerate(VERDICTS)}
    return sorted(findings, key=lambda f: (sev.get(f.severity, len(sev)), order.get(f.verdict, len(order)), f.id))


def _findings_sheet(ws, job, gitlab_url: str):
    for col, (name, width, _) in enumerate(COLUMNS, 1):
        _put(ws, 1, col, name, font=HEAD_FONT, fill=HEAD_FILL, align=Alignment(vertical="center", wrap_text=True))
        ws.column_dimensions[get_column_letter(col)].width = width
    ws.row_dimensions[1].height = 30

    findings = _sorted(job.findings)
    for row, f in enumerate(findings, 2):
        posted = posted_note(f)
        mr = fix_mr(f)
        verdict = _verdict(f)
        issue_url = (posted.get("url") or "").split("#note_")[0] if posted else ""
        vuln_url = vulnerability_url(f, job, gitlab_url)
        vuln_label = (f"Vulnerability #{f.vulnerability_gid.rsplit('/', 1)[-1]}" if f.vulnerability_gid
                      else "Pipeline security report" if vuln_url else "")
        copied = (f.copied_from or {}).get("job") if f.status == "done" else None
        fix = "Yes" if f.fix and f.diff else "No"
        severity = (f.severity or "unknown").lower()
        values = [
            (row - 1, {"align": CENTER}),
            (severity.capitalize(), {"style": SEV_STYLE.get(severity, SEV_STYLE["unknown"]), "align": CENTER}),
            (verdict, {"style": VERDICT_STYLE.get(verdict), "align": CENTER}),
            (round(f.confidence, 3) if f.confidence is not None and f.status == "done" else "", {"fmt": "0%", "align": CENTER}),
            (f.title, {"align": WRAP}),
            (f.cwe or "", {}),
            (_location(f), {"link": _blob_url(f, job, gitlab_url) if f.file else None, "align": WRAP}),
            (f"#{posted['issue_iid']}" if posted and posted.get("issue_iid") else ("Posted" if posted else ""),
             {"link": issue_url or None, "align": CENTER}),
            (vuln_label, {"link": vuln_url}),
            ("Yes" if posted else "No", {"style": YES_NO_STYLE["Yes" if posted else "No"], "align": CENTER}),
            (posted.get("by", "") if posted else "", {}),
            (_when(posted.get("at")) if posted else "", {}),
            (fix, {"align": CENTER}),
            (VALIDATION.get(f.validation_status, f.validation_status or "") if fix == "Yes" else "", {}),
            (f"!{mr['mr_iid']}" if mr and mr.get("mr_iid") else ("Opened" if mr else ""), {"link": mr and mr.get("url"), "align": CENTER}),
            ("Yes" if _action(f, "dismissed") else "No", {"align": CENTER}),
            (f"#{copied}" if copied else "", {"align": CENTER}),
            (f.scanner or "", {}),
            (STATUSES.get(f.status, f.status), {}),
            # A copied analysis didn't ask the model: no time or tokens of its own worth comparing.
            (round(f.duration_s, 1) if f.duration_s is not None and not copied else "", {"fmt": "0.0", "align": CENTER}),
            ((f.completion_tokens or "") if not copied else "", {"fmt": "#,##0", "align": CENTER}),
            (f.reasoning or "", {"align": WRAP}),
            (f.error or "", {"align": WRAP}),
        ]
        band = PatternFill("solid", fgColor=BAND) if row % 2 else None
        for col, (value, opts) in enumerate(values, 1):
            cell = _put(ws, row, col, value, fill=band, **opts)
            cell.border = BORDER
        # Long reasoning would make rows huge; Excel grows them as needed up to this cap.
        ws.row_dimensions[row].height = min(150, max(30, 15 * (1 + len(f.reasoning or "") // 160)))

    last = max(2, len(findings) + 1)
    ref = f"A1:{get_column_letter(len(COLUMNS))}{last}"
    if findings:
        table = Table(displayName="FindingsTable", ref=ref)
        table.tableStyleInfo = TableStyleInfo(name="TableStyleLight1", showRowStripes=False)
        ws.add_table(table)
    ws.freeze_panes = "F2"
    ws.sheet_view.zoomScale = 100
    ws.print_title_rows = "1:1"
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.sheet_properties.tabColor = NAVY


def _summary_sheet(ws, job, gitlab_url: str, generated_by: str):
    ws.sheet_view.showGridLines = False
    ws.column_dimensions["A"].width = 3
    for col, width in zip("BCDEFGHI", (24, 14, 14, 14, 14, 14, 14, 14)):
        ws.column_dimensions[col].width = width

    ws.merge_cells("B2:I2")
    _put(ws, 2, 2, "SecureFix analysis report", font=Font(name="Calibri", bold=True, size=20, color="FFFFFF"),
         fill=HEAD_FILL, align=Alignment(vertical="center", indent=1))
    for col in range(3, 10):
        ws.cell(row=2, column=col).fill = HEAD_FILL
    ws.row_dimensions[2].height = 40
    ws.merge_cells("B3:I3")
    _put(ws, 3, 2, f"{job.project_path} · {job.branch} · {job.sha[:8]}",
         font=Font(name="Calibri", italic=True, size=11, color=MUTED), align=Alignment(indent=1))

    label_font = Font(name="Calibri", bold=True, color=MUTED, size=10.5)
    project_url = f"{gitlab_url}/{job.project_path}"
    details = [
        ("Project", job.project_path, project_url),
        ("Branch", job.branch, None),
        ("Commit", job.sha, f"{project_url}/-/commit/{job.sha}"),
        ("Analysis", f"#{job.id}", None),
        ("Started by", job.user.username if job.user else "", None),
        ("Status", (job.status or "").capitalize(), None),
        ("Started", _when(job.created_at), None),
        ("Finished", _when(job.finished_at), None),
        ("Severities analyzed", ", ".join(s.capitalize() for s in job.severities) if job.severities else "All", None),
        ("Model thinking", (job.thinking or "on").capitalize(), None),
        ("Code per finding", f"up to {job.budget:,} tokens", None),
        ("Analysis time", _duration(job.findings), None),
        ("Report generated", f"{_when(datetime.now(timezone.utc))} by {generated_by}", None),
    ]
    row = 5
    _put(ws, row, 2, "Details", font=Font(name="Calibri", bold=True, size=13, color=NAVY))
    for label, value, link in details:
        row += 1
        _put(ws, row, 2, label, font=label_font)
        ws.merge_cells(start_row=row, start_column=3, end_row=row, end_column=9)
        _put(ws, row, 3, value, link=link)

    findings = job.findings
    verdicts = {}
    for f in findings:
        verdicts[_verdict(f)] = verdicts.get(_verdict(f), 0) + 1
    posted = sum(1 for f in findings if posted_note(f))
    analyzed = sum(1 for f in findings if f.status == "done")

    row += 2
    _put(ws, row, 2, "Totals", font=Font(name="Calibri", bold=True, size=13, color=NAVY))
    row += 1
    tiles = [("Findings", len(findings), (NAVY, "FFFFFF")), ("Real", verdicts.get("Real", 0), VERDICT_STYLE["Real"]),
             ("Needs review", verdicts.get("Needs review", 0), VERDICT_STYLE["Needs review"]),
             ("False positive", verdicts.get("False positive", 0), VERDICT_STYLE["False positive"]),
             ("Skipped", verdicts.get("Skipped", 0), VERDICT_STYLE["Skipped"]),
             ("Error", verdicts.get("Error", 0), VERDICT_STYLE["Error"]),
             ("Posted", f"{posted}/{analyzed}", YES_NO_STYLE["Yes"])]
    for i, (label, value, (bg, fg)) in enumerate(tiles):
        fill = PatternFill("solid", fgColor=bg)
        _put(ws, row, 2 + i, value, fill=fill, font=Font(name="Calibri", bold=True, size=18, color=fg),
             align=Alignment(horizontal="center", vertical="center")).border = BORDER
        _put(ws, row + 1, 2 + i, label, fill=fill, font=Font(name="Calibri", bold=True, size=10, color=fg),
             align=Alignment(horizontal="center", vertical="center")).border = BORDER
    ws.row_dimensions[row].height = 32
    ws.row_dimensions[row + 1].height = 20

    row += 3
    _put(ws, row, 2, "By severity", font=Font(name="Calibri", bold=True, size=13, color=NAVY))
    row += 1
    heads = ["Severity", "Real", "Needs review", "False positive", "Skipped", "Other", "Total", "Posted"]
    for i, h in enumerate(heads):
        _put(ws, row, 2 + i, h, font=HEAD_FONT, fill=HEAD_FILL,
             align=Alignment(horizontal="center", vertical="center", wrap_text=True)).border = BORDER
    ws.row_dimensions[row].height = 30
    present = [s for s in SEVERITIES if any((f.severity or "unknown").lower() == s for f in findings)]
    present += sorted({(f.severity or "unknown").lower() for f in findings} - set(SEVERITIES))
    for sev in present:
        row += 1
        group = [f for f in findings if (f.severity or "unknown").lower() == sev]
        counts = [sum(1 for f in group if _verdict(f) == v) for v in ("Real", "Needs review", "False positive", "Skipped")]
        cells = [sev.capitalize(), *counts, len(group) - sum(counts), len(group),
                 sum(1 for f in group if posted_note(f))]
        for i, value in enumerate(cells):
            style = SEV_STYLE.get(sev, SEV_STYLE["unknown"]) if i == 0 else None
            _put(ws, row, 2 + i, value, style=style, align=Alignment(horizontal="center")).border = BORDER
    if not present:
        row += 1
        ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=9)
        _put(ws, row, 2, "This analysis has no findings.", font=Font(name="Calibri", italic=True, color=MUTED))

    row += 2
    ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=9)
    _put(ws, row, 2, "Every finding, with its GitLab issue and vulnerability links, is on the Findings sheet.",
         font=Font(name="Calibri", italic=True, color=MUTED))
    ws.page_setup.orientation = "portrait"
    ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True


def build_report(job, gitlab_url: str, generated_by: str) -> bytes:
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"
    _summary_sheet(summary, job, gitlab_url, generated_by)
    _findings_sheet(wb.create_sheet("Findings"), job, gitlab_url)
    wb.properties.title = f"SecureFix analysis #{job.id}"
    wb.properties.creator = "SecureFix"
    out = BytesIO()
    wb.save(out)
    return out.getvalue()


def filename(job) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", job.project_path).strip("-")[:80] or "project"
    return f"securefix-{slug}-{job.sha[:8]}-analysis-{job.id}.xlsx"
