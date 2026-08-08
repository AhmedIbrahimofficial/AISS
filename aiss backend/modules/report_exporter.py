"""AISS - Report Exporter
Generates visual threat reports using matplotlib, plotly, openpyxl, and xlsxwriter.

Exports:
  - Excel workbook (openpyxl / xlsxwriter) — full threat table + charts
  - PNG charts (matplotlib) — severity pie, timeline bar
  - Interactive HTML (plotly) — timeline + heatmap

Usage:
    from modules.report_exporter import report_exporter
    xlsx_bytes = await report_exporter.export_excel(threats)
    png_bytes  = await report_exporter.export_chart_png(threats)
    html_str   = await report_exporter.export_plotly_html(threats)
"""
import asyncio
import io
import os
from collections import Counter
from datetime import datetime
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("report_exporter")


class ReportExporter:
    def __init__(self):
        self._matplotlib = None
        self._plotly     = None
        self._openpyxl   = None
        self._xlsxwriter = None
        self._scipy      = None
        self._tried      = False

    def _lazy_init(self):
        if self._tried:
            return
        self._tried = True
        try:
            import matplotlib
            matplotlib.use("Agg")   # non-interactive backend (no display needed)
            import matplotlib.pyplot as plt
            self._matplotlib = plt
        except Exception as e:
            logger.debug(f"matplotlib unavailable: {e}")
        try:
            import plotly.express as px
            import plotly.graph_objects as go
            self._plotly = (px, go)
        except Exception as e:
            logger.debug(f"plotly unavailable: {e}")
        try:
            import openpyxl
            self._openpyxl = openpyxl
        except Exception as e:
            logger.debug(f"openpyxl unavailable: {e}")
        try:
            import xlsxwriter
            self._xlsxwriter = xlsxwriter
        except Exception as e:
            logger.debug(f"xlsxwriter unavailable: {e}")
        try:
            import scipy
            self._scipy = scipy
        except Exception as e:
            logger.debug(f"scipy unavailable: {e}")

    # ── Excel Export ─────────────────────────────────────────────────

    async def export_excel(self, threats: list[dict]) -> Optional[bytes]:
        """
        Export threats to an Excel workbook.
        Uses xlsxwriter for rich formatting (conditional colors, charts).
        Falls back to openpyxl if xlsxwriter is unavailable.
        """
        self._lazy_init()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._build_excel(threats))

    def _build_excel(self, threats: list[dict]) -> Optional[bytes]:
        if self._xlsxwriter:
            return self._build_excel_xlsxwriter(threats)
        if self._openpyxl:
            return self._build_excel_openpyxl(threats)
        return None

    def _build_excel_xlsxwriter(self, threats: list[dict]) -> bytes:
        buf = io.BytesIO()
        wb  = self._xlsxwriter.Workbook(buf, {"in_memory": True})
        ws  = wb.add_worksheet("Threats")

        # Formats
        hdr_fmt  = wb.add_format({"bold": True, "bg_color": "#16213e", "font_color": "white", "border": 1})
        crit_fmt = wb.add_format({"bg_color": "#FF4444", "font_color": "white"})
        high_fmt = wb.add_format({"bg_color": "#FF8C00", "font_color": "white"})
        med_fmt  = wb.add_format({"bg_color": "#FFD700"})
        low_fmt  = wb.add_format({"bg_color": "#90EE90"})

        headers = ["ID", "Type", "Severity", "Source", "Status", "Detected At", "Description"]
        for col, h in enumerate(headers):
            ws.write(0, col, h, hdr_fmt)
        ws.set_column("A:A", 10)
        ws.set_column("B:B", 22)
        ws.set_column("C:C", 12)
        ws.set_column("D:D", 22)
        ws.set_column("E:E", 12)
        ws.set_column("F:F", 20)
        ws.set_column("G:G", 60)

        sev_fmt = {"critical": crit_fmt, "high": high_fmt, "medium": med_fmt, "low": low_fmt}

        for row, t in enumerate(threats[:5000], start=1):
            sev = str(t.get("severity", "")).lower()
            fmt = sev_fmt.get(sev)
            ws.write(row, 0, str(t.get("id", ""))[:10], fmt)
            ws.write(row, 1, str(t.get("type", "")),      fmt)
            ws.write(row, 2, sev.upper(),                 fmt)
            ws.write(row, 3, str(t.get("source", ""))[:40], fmt)
            ws.write(row, 4, str(t.get("status", "")),    fmt)
            ws.write(row, 5, str(t.get("detected_at", ""))[:20], fmt)
            ws.write(row, 6, str(t.get("description", ""))[:200], fmt)

        # Summary sheet
        ws2 = wb.add_worksheet("Summary")
        counts = Counter(str(t.get("severity","")).lower() for t in threats)
        ws2.write(0, 0, "Severity",  hdr_fmt)
        ws2.write(0, 1, "Count",     hdr_fmt)
        for i, (sev, cnt) in enumerate(counts.most_common(), start=1):
            ws2.write(i, 0, sev.upper())
            ws2.write(i, 1, cnt)

        # Severity pie chart
        chart = wb.add_chart({"type": "pie"})
        chart.add_series({
            "name":       "Severity Distribution",
            "categories": ["Summary", 1, 0, len(counts), 0],
            "values":     ["Summary", 1, 1, len(counts), 1],
        })
        chart.set_title({"name": "Threat Severity Distribution"})
        ws2.insert_chart("D2", chart, {"x_scale": 2, "y_scale": 2})

        wb.close()
        return buf.getvalue()

    def _build_excel_openpyxl(self, threats: list[dict]) -> bytes:
        from openpyxl.styles import PatternFill, Font, Alignment
        wb = self._openpyxl.Workbook()
        ws = wb.active
        ws.title = "Threats"

        headers = ["ID", "Type", "Severity", "Source", "Status", "Detected At", "Description"]
        ws.append(headers)
        for cell in ws[1]:
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill("solid", fgColor="16213E")

        sev_colors = {"critical": "FF4444", "high": "FF8C00", "medium": "FFD700", "low": "90EE90"}
        for t in threats[:5000]:
            sev = str(t.get("severity", "")).lower()
            row_data = [
                str(t.get("id", ""))[:10],
                str(t.get("type", "")),
                sev.upper(),
                str(t.get("source", ""))[:40],
                str(t.get("status", "")),
                str(t.get("detected_at", ""))[:20],
                str(t.get("description", ""))[:200],
            ]
            ws.append(row_data)
            color = sev_colors.get(sev, "FFFFFF")
            for cell in ws[ws.max_row]:
                cell.fill = PatternFill("solid", fgColor=color)

        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    # ── Matplotlib PNG chart ──────────────────────────────────────────

    async def export_chart_png(self, threats: list[dict]) -> Optional[bytes]:
        """Generate severity distribution pie chart as PNG bytes."""
        self._lazy_init()
        if not self._matplotlib:
            return None
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._build_chart(threats))

    def _build_chart(self, threats: list[dict]) -> bytes:
        plt = self._matplotlib
        counts = Counter(str(t.get("severity", "")).lower() for t in threats)
        labels = [k.upper() for k in counts.keys()]
        values = list(counts.values())
        colors = {"CRITICAL": "#FF4444", "HIGH": "#FF8C00", "MEDIUM": "#FFD700", "LOW": "#90EE90"}
        clrs   = [colors.get(l, "#AAAAAA") for l in labels]

        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        fig.patch.set_facecolor("#1a1a2e")

        # Pie
        ax1 = axes[0]
        ax1.set_facecolor("#16213e")
        if values:
            wedges, texts, autotexts = ax1.pie(
                values, labels=labels, colors=clrs, autopct="%1.1f%%",
                textprops={"color": "white"}, startangle=140
            )
            for at in autotexts:
                at.set_color("white")
        ax1.set_title("Severity Distribution", color="white", fontsize=14)

        # Bar timeline (threats per hour)
        ax2 = axes[1]
        ax2.set_facecolor("#16213e")
        hours = []
        for t in threats:
            try:
                dt = datetime.fromisoformat(str(t.get("detected_at", ""))[:19])
                hours.append(dt.strftime("%H:00"))
            except Exception:
                pass
        if hours:
            hcounts = Counter(hours)
            sorted_h = sorted(hcounts.keys())
            ax2.bar(sorted_h, [hcounts[h] for h in sorted_h], color="#00b4d8")
            ax2.set_xlabel("Hour", color="white")
            ax2.set_ylabel("Threats", color="white")
            ax2.tick_params(colors="white", rotation=45)
            ax2.set_title("Threats by Hour", color="white", fontsize=14)
            ax2.spines["bottom"].set_color("white")
            ax2.spines["left"].set_color("white")

        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                    facecolor=fig.get_facecolor())
        plt.close(fig)
        return buf.getvalue()

    # ── Plotly interactive HTML ───────────────────────────────────────

    async def export_plotly_html(self, threats: list[dict]) -> Optional[str]:
        """Generate an interactive Plotly HTML dashboard string."""
        self._lazy_init()
        if not self._plotly:
            return None
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._build_plotly(threats))

    def _build_plotly(self, threats: list[dict]) -> str:
        px, go = self._plotly
        import pandas as pd

        df = pd.DataFrame([{
            "type":        str(t.get("type",     "")),
            "severity":    str(t.get("severity", "")).upper(),
            "source":      str(t.get("source",   ""))[:30],
            "status":      str(t.get("status",   "")),
            "detected_at": str(t.get("detected_at", ""))[:19],
        } for t in threats[:500]])

        if df.empty:
            return "<html><body><p>No threat data</p></body></html>"

        fig = go.Figure()

        # Severity counts bar
        counts = df["severity"].value_counts()
        color_map = {"CRITICAL": "#FF4444", "HIGH": "#FF8C00", "MEDIUM": "#FFD700", "LOW": "#90EE90"}
        fig.add_trace(go.Bar(
            x=counts.index.tolist(),
            y=counts.values.tolist(),
            marker_color=[color_map.get(s, "#AAAAAA") for s in counts.index],
            name="Threats by Severity",
        ))
        fig.update_layout(
            title="AISS Threat Dashboard",
            template="plotly_dark",
            paper_bgcolor="#1a1a2e",
            plot_bgcolor="#16213e",
            font_color="white",
        )
        return fig.to_html(include_plotlyjs="cdn", full_html=True)

    def is_available(self) -> dict:
        self._lazy_init()
        return {
            "matplotlib": self._matplotlib is not None,
            "plotly":     self._plotly is not None,
            "openpyxl":   self._openpyxl is not None,
            "xlsxwriter": self._xlsxwriter is not None,
            "scipy":      self._scipy is not None,
        }


# Singleton
report_exporter = ReportExporter()
