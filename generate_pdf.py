import os
import subprocess
import re

# Read Markdown document
md_file_path = r"c:\Users\DELL\OneDrive\Desktop\SIH'26\TheThirdEye\PROJECT_DOCUMENTATION.md"
html_file_path = r"c:\Users\DELL\OneDrive\Desktop\SIH'26\TheThirdEye\PROJECT_DOCUMENTATION.html"
pdf_file_path = r"c:\Users\DELL\OneDrive\Desktop\SIH'26\TheThirdEye\CyberShield_Project_Specification.pdf"

with open(md_file_path, "r", encoding="utf-8") as f:
    md_content = f.read()

# Try installing markdown library if missing
try:
    import markdown
except ImportError:
    subprocess.run(["pip", "install", "markdown"], check=True)
    import markdown

# Convert MD to HTML with extensions
html_body = markdown.markdown(
    md_content,
    extensions=['tables', 'fenced_code', 'codehilite', 'toc']
)

# Wrap in a gorgeous printable CSS template
html_full = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberShield — Project Specification & Technical Documentation</title>
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap');

    @page {{
        size: A4;
        margin: 20mm 15mm 20mm 15mm;
        @bottom-right {{
            content: counter(page);
        }}
    }}

    body {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        color: #1e293b;
        background-color: #ffffff;
        line-height: 1.6;
        font-size: 13px;
        padding: 20px 30px;
    }}

    h1 {{
        font-size: 26px;
        font-weight: 800;
        color: #0f172a;
        border-bottom: 3px solid #2563eb;
        padding-bottom: 10px;
        margin-top: 0;
        margin-bottom: 15px;
    }}

    h2 {{
        font-size: 18px;
        font-weight: 700;
        color: #1e293b;
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 6px;
        margin-top: 25px;
        margin-bottom: 12px;
        page-break-after: avoid;
    }}

    h3 {{
        font-size: 15px;
        font-weight: 600;
        color: #2563eb;
        margin-top: 18px;
        margin-bottom: 8px;
        page-break-after: avoid;
    }}

    blockquote {{
        background: #f8fafc;
        border-left: 4px solid #2563eb;
        margin: 15px 0;
        padding: 10px 15px;
        color: #334155;
        font-weight: 500;
        border-radius: 0 6px 6px 0;
    }}

    p, li {{
        color: #334155;
    }}

    ul, ol {{
        padding-left: 20px;
    }}

    li {{
        margin-bottom: 4px;
    }}

    table {{
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
        font-size: 12px;
        page-break-inside: avoid;
    }}

    th {{
        background-color: #0f172a;
        color: #ffffff;
        font-weight: 600;
        text-align: left;
        padding: 8px 12px;
        border: 1px solid #0f172a;
    }}

    td {{
        padding: 8px 12px;
        border: 1px solid #e2e8f0;
    }}

    tr:nth-child(even) {{
        background-color: #f8fafc;
    }}

    code {{
        font-family: 'Fira Code', Consolas, Monaco, monospace;
        background-color: #f1f5f9;
        color: #0f172a;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 11.5px;
    }}

    pre {{
        background-color: #0f172a;
        color: #f8fafc;
        padding: 14px;
        border-radius: 8px;
        overflow-x: auto;
        font-family: 'Fira Code', Consolas, Monaco, monospace;
        font-size: 11px;
        line-height: 1.5;
        page-break-inside: avoid;
    }}

    pre code {{
        background-color: transparent;
        color: #f8fafc;
        padding: 0;
    }}

    hr {{
        border: none;
        border-top: 1px solid #e2e8f0;
        margin: 25px 0;
    }}

    img {{
        max-width: 100%;
        height: auto;
    }}

    .badge {{
        display: inline-block;
        padding: 3px 8px;
        font-size: 11px;
        font-weight: 600;
        border-radius: 12px;
        background: #e0e7ff;
        color: #3730a3;
    }}
</style>
</head>
<body>
{html_body}
</body>
</html>
"""

with open(html_file_path, "w", encoding="utf-8") as f:
    f.write(html_full)

print(f"[OK] Generated HTML: {html_file_path}")

# Run Microsoft Edge headless to generate PDF
edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

cmd = [
    edge_path,
    "--headless",
    "--disable-gpu",
    f"--print-to-pdf={pdf_file_path}",
    "--no-margins",
    html_file_path
]

subprocess.run(cmd, check=True)
print(f"[SUCCESS] PDF generated at: {pdf_file_path}")
