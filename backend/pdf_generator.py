from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import os

template_dir = os.path.join(os.path.dirname(__file__), "..", "frontend", "templates")


def generate_pdf_report(scan_data: dict, user_name: str) -> bytes:
    """Render HTML report and convert to PDF via WeasyPrint."""
    from weasyprint import HTML, CSS

    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html")

    html_content = template.render(
        scan=scan_data,
        user_name=user_name,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        severity_color=_severity_color,
    )

    pdf_bytes = HTML(string=html_content, base_url=template_dir).write_pdf()
    return pdf_bytes


def _severity_color(severity: str) -> str:
    return {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#65a30d",
        "info": "#0ea5e9",
        "unknown": "#6b7280",
    }.get(severity.lower() if severity else "unknown", "#6b7280")
