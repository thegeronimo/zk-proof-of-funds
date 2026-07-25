#!/usr/bin/env python3
"""Convert the overview markdown to a styled HTML, then to PDF via weasyprint."""

import markdown
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
MD_FILE = SCRIPT_DIR / "ZK_PROOF_OF_FUNDS_OVERVIEW.md"
HTML_FILE = SCRIPT_DIR / "ZK_PROOF_OF_FUNDS_OVERVIEW.html"
PDF_FILE = SCRIPT_DIR / "ZK_PROOF_OF_FUNDS_OVERVIEW.pdf"

CSS = """
@page {
    size: A4;
    margin: 2cm 2.5cm;
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9px;
        color: #888;
        font-family: 'Helvetica Neue', Arial, sans-serif;
    }
    @top-right {
        content: "ZK Proof of Funds";
        font-size: 9px;
        color: #888;
        font-family: 'Helvetica Neue', Arial, sans-serif;
    }
}

body {
    font-family: 'Helvetica Neue', Arial, sans-serif;
    font-size: 11px;
    line-height: 1.65;
    color: #1a1a2e;
    max-width: 100%;
}

h1 {
    font-size: 26px;
    font-weight: 700;
    color: #0f0f23;
    margin-top: 2em;
    margin-bottom: 0.5em;
    padding-bottom: 0.3em;
    border-bottom: 3px solid #4361ee;
    page-break-after: avoid;
}

h1:first-of-type {
    font-size: 32px;
    text-align: center;
    border-bottom: none;
    margin-top: 0;
    color: #4361ee;
}

h2 {
    font-size: 18px;
    font-weight: 600;
    color: #2d2d5e;
    margin-top: 1.8em;
    margin-bottom: 0.6em;
    padding-bottom: 0.2em;
    border-bottom: 1px solid #ddd;
    page-break-after: avoid;
}

h3 {
    font-size: 14px;
    font-weight: 600;
    color: #3a3a6e;
    margin-top: 1.4em;
    margin-bottom: 0.4em;
    page-break-after: avoid;
}

p {
    margin-bottom: 0.8em;
}

strong {
    color: #0f0f23;
}

code {
    font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 10px;
    background: #f4f4f8;
    padding: 1px 4px;
    border-radius: 3px;
    color: #4361ee;
}

pre {
    background: #f8f8fc;
    border: 1px solid #e0e0ea;
    border-left: 4px solid #4361ee;
    border-radius: 6px;
    padding: 12px 16px;
    margin: 1em 0;
    overflow-x: auto;
    page-break-inside: avoid;
}

pre code {
    background: none;
    padding: 0;
    color: #1a1a2e;
    font-size: 9.5px;
    line-height: 1.5;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 1em 0;
    font-size: 10.5px;
    page-break-inside: avoid;
}

thead {
    background: #4361ee;
    color: white;
}

th {
    padding: 8px 12px;
    text-align: left;
    font-weight: 600;
    font-size: 10px;
}

td {
    padding: 7px 12px;
    border-bottom: 1px solid #eee;
}

tr:nth-child(even) td {
    background: #fafaff;
}

blockquote {
    border-left: 4px solid #4361ee;
    margin: 1em 0;
    padding: 0.5em 1em;
    background: #f8f8fc;
    color: #555;
}

hr {
    border: none;
    border-top: 2px solid #eee;
    margin: 2em 0;
}

ul, ol {
    margin-bottom: 0.8em;
    padding-left: 1.5em;
}

li {
    margin-bottom: 0.3em;
}

/* Title page styling */
p:first-of-type {
    text-align: center;
    color: #666;
    font-style: italic;
}

/* Subtitle line */
body > p:nth-of-type(2) {
    text-align: center;
    color: #888;
    font-size: 10px;
}
"""

def main():
    md_text = MD_FILE.read_text(encoding="utf-8")

    # Convert markdown to HTML
    extensions = ["tables", "fenced_code", "codehilite", "toc"]
    html_body = markdown.markdown(md_text, extensions=extensions)

    # Wrap in full HTML doc
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ZK Proof of Funds - System Overview</title>
    <style>{CSS}</style>
</head>
<body>
{html_body}
</body>
</html>"""

    HTML_FILE.write_text(html_doc, encoding="utf-8")
    print(f"HTML written to {HTML_FILE}")

    # Convert to PDF with weasyprint
    try:
        from weasyprint import HTML as WeasyHTML
        WeasyHTML(filename=str(HTML_FILE)).write_pdf(str(PDF_FILE))
        print(f"PDF written to {PDF_FILE}")
    except ImportError:
        print("weasyprint not available, trying command line...")
        import subprocess
        subprocess.run(["weasyprint", str(HTML_FILE), str(PDF_FILE)], check=True)
        print(f"PDF written to {PDF_FILE}")


if __name__ == "__main__":
    main()
