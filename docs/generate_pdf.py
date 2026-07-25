#!/usr/bin/env python3
"""Generate a styled PDF from the overview markdown using fpdf2's HTML parser."""

from fpdf import FPDF
from pathlib import Path
import re

SCRIPT_DIR = Path(__file__).parent
MD_FILE = SCRIPT_DIR / "ZK_PROOF_OF_FUNDS_OVERVIEW.md"
PDF_FILE = SCRIPT_DIR / "ZK_PROOF_OF_FUNDS_OVERVIEW.pdf"


class StyledPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        if self.page_no() > 1:
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, "ZK Proof of Funds - System Overview", align="R")
            self.ln(5)
            self.set_draw_color(220, 220, 220)
            self.line(10, self.get_y(), self.w - 10, self.get_y())
            self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


def parse_table(lines, start_idx):
    """Parse a markdown table starting at start_idx, return (rows, end_idx)."""
    rows = []
    i = start_idx
    while i < len(lines) and lines[i].strip().startswith("|"):
        cells = [c.strip() for c in lines[i].strip().split("|")[1:-1]]
        rows.append(cells)
        i += 1
    # Remove separator row (row with ----)
    if len(rows) > 1 and all(re.match(r'^[-:\s]+$', c) for c in rows[1]):
        rows.pop(1)
    return rows, i


def render_table(pdf, rows):
    """Render a table to the PDF."""
    if not rows:
        return

    ncols = len(rows[0])
    available_width = pdf.w - 20  # margins
    col_width = available_width / ncols

    # Estimate column widths based on content
    max_lens = [0] * ncols
    for row in rows:
        for j, cell in enumerate(row):
            if j < ncols:
                max_lens[j] = max(max_lens[j], len(cell))

    total_len = sum(max_lens) or 1
    col_widths = [(ml / total_len) * available_width for ml in max_lens]
    # Ensure minimum width
    col_widths = [max(w, 20) for w in col_widths]
    # Normalize
    total_w = sum(col_widths)
    col_widths = [w * available_width / total_w for w in col_widths]

    row_height = 7

    for i, row in enumerate(rows):
        # Check if we need a new page
        if pdf.get_y() + row_height > pdf.h - 25:
            pdf.add_page()

        if i == 0:
            # Header row
            pdf.set_fill_color(67, 97, 238)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 9)
        else:
            if i % 2 == 0:
                pdf.set_fill_color(248, 248, 255)
            else:
                pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(40, 40, 60)
            pdf.set_font("Helvetica", "", 9)

        x_start = pdf.get_x()
        max_cell_h = row_height

        for j, cell in enumerate(row):
            if j < ncols:
                w = col_widths[j]
                # Calculate needed height
                text = cell.replace("**", "").strip()
                lines_needed = max(1, len(text) * pdf.get_string_width("a") / (w - 2))
                cell_h = max(row_height, int(lines_needed) * 4 + 4)
                max_cell_h = max(max_cell_h, cell_h)

        for j, cell in enumerate(row):
            if j < ncols:
                w = col_widths[j]
                text = cell.replace("**", "").strip()
                text = text.encode('latin-1', errors='replace').decode('latin-1')
                pdf.cell(w, max_cell_h, text[:int(w/2.2)], border=0, fill=True)

        pdf.ln(max_cell_h)

    # Draw bottom border
    pdf.set_draw_color(220, 220, 220)
    pdf.line(10, pdf.get_y(), pdf.w - 10, pdf.get_y())
    pdf.ln(3)


def clean_inline(text):
    """Remove markdown inline formatting for plain text."""
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
    text = re.sub(r'\*(.*?)\*', r'\1', text)
    text = re.sub(r'`(.*?)`', r'\1', text)
    text = re.sub(r'\[(.*?)\]\(.*?\)', r'\1', text)
    # Replace unicode chars that Helvetica can't handle
    text = text.replace('\u2014', '--')
    text = text.replace('\u2013', '-')
    text = text.replace('\u2018', "'")
    text = text.replace('\u2019', "'")
    text = text.replace('\u201c', '"')
    text = text.replace('\u201d', '"')
    text = text.replace('\u2022', '-')
    text = text.replace('\u2026', '...')
    text = text.replace('\u2192', '->')
    text = text.replace('\u2190', '<-')
    text = text.replace('\u2194', '<->')
    text = text.replace('\u25b6', '>')
    text = text.replace('\u25bc', 'v')
    text = text.replace('\u2500', '-')
    text = text.replace('\u2502', '|')
    text = text.replace('\u250c', '+')
    text = text.replace('\u2510', '+')
    text = text.replace('\u2514', '+')
    text = text.replace('\u2518', '+')
    # Remove any remaining non-latin1 chars
    text = text.encode('latin-1', errors='replace').decode('latin-1')
    return text.strip()


def main():
    pdf = StyledPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    lines = MD_FILE.read_text(encoding="utf-8").split("\n")

    # ─── Title page ─────────────────────────────────────────
    pdf.ln(40)
    pdf.set_font("Helvetica", "B", 32)
    pdf.set_text_color(67, 97, 238)
    pdf.cell(0, 15, "ZK Proof of Funds", ln=True, align="C")
    pdf.ln(5)
    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(80, 80, 120)
    pdf.cell(0, 10, "System Overview", ln=True, align="C")
    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 13)
    pdf.set_text_color(100, 100, 140)
    pdf.cell(0, 8, "Privacy-Preserving Solvency Attestation", ln=True, align="C")
    pdf.cell(0, 8, "for EVM Networks", ln=True, align="C")
    pdf.ln(20)
    pdf.set_draw_color(67, 97, 238)
    pdf.set_line_width(0.5)
    pdf.line(60, pdf.get_y(), pdf.w - 60, pdf.get_y())
    pdf.ln(15)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(120, 120, 140)
    pdf.cell(0, 8, "Version 1.0  |  February 2026", ln=True, align="C")
    pdf.ln(40)

    # ─── TOC placeholder ─────────────────────────────────────
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(80, 80, 100)
    pdf.cell(0, 7, "Table of Contents", ln=True, align="C")
    pdf.ln(3)
    toc_items = [
        "1.  What is ZK Proof of Funds?",
        "2.  How It Works (Simple Version)",
        "3.  System Architecture",
        "4.  For End Users (Members)",
        "5.  For Service Providers (Relying Protocols)",
        "6.  For Operators (Running the Solvency Agent)",
        "7.  Privacy & Security Model",
        "8.  Worked Example: Tiered Credit Card Program",
        "9.  Technical Reference",
        "10. Glossary",
    ]
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 90)
    for item in toc_items:
        pdf.cell(0, 6, item, ln=True, align="C")

    # ─── Content ─────────────────────────────────────────────
    pdf.add_page()

    i = 0
    in_code_block = False
    code_lines = []

    while i < len(lines):
        line = lines[i]

        # Skip the title and subtitle (already on title page)
        if i < 8:
            i += 1
            continue

        # Skip TOC section
        if line.strip().startswith("## Table of Contents"):
            # Skip until next ##
            i += 1
            while i < len(lines) and not (lines[i].startswith("## ") and "Table of Contents" not in lines[i]):
                i += 1
            continue

        # Code blocks
        if line.strip().startswith("```"):
            if in_code_block:
                # End code block - render collected lines
                in_code_block = False
                pdf.set_font("Courier", "", 8)
                pdf.set_text_color(40, 40, 60)
                pdf.set_fill_color(248, 248, 252)
                pdf.set_draw_color(67, 97, 238)

                # Draw left border and background
                x = pdf.get_x()
                y = pdf.get_y()
                block_h = len(code_lines) * 4 + 6

                # Check for page break
                if y + block_h > pdf.h - 25:
                    pdf.add_page()
                    y = pdf.get_y()

                pdf.set_fill_color(248, 248, 252)
                pdf.rect(12, y, pdf.w - 24, block_h, "F")
                pdf.set_draw_color(67, 97, 238)
                pdf.line(12, y, 12, y + block_h)

                pdf.set_xy(16, y + 3)
                for cl in code_lines:
                    if pdf.get_y() + 4 > pdf.h - 25:
                        pdf.add_page()
                    safe_cl = cl.encode('latin-1', errors='replace').decode('latin-1')
                    pdf.cell(0, 4, safe_cl[:100], ln=True)
                    pdf.set_x(16)

                pdf.ln(4)
                code_lines = []
            else:
                in_code_block = True
                code_lines = []
            i += 1
            continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        # Horizontal rules
        if line.strip() == "---":
            pdf.ln(3)
            pdf.set_draw_color(220, 220, 230)
            pdf.line(10, pdf.get_y(), pdf.w - 10, pdf.get_y())
            pdf.ln(3)
            i += 1
            continue

        # H1 headings
        if line.startswith("# ") and not line.startswith("## "):
            text = line[2:].strip()
            # Skip the main title (already on title page)
            if "ZK Proof of Funds" in text and "System Overview" not in text:
                i += 1
                continue
            pdf.ln(8)
            pdf.set_font("Helvetica", "B", 22)
            pdf.set_text_color(67, 97, 238)
            pdf.cell(0, 12, clean_inline(text), ln=True)
            pdf.set_draw_color(67, 97, 238)
            pdf.line(10, pdf.get_y(), pdf.w - 10, pdf.get_y())
            pdf.ln(5)
            i += 1
            continue

        # H2 headings
        if line.startswith("## "):
            text = line[3:].strip()
            # Start a new page for major sections
            if pdf.get_y() > 200:
                pdf.add_page()
            else:
                pdf.ln(8)

            pdf.set_font("Helvetica", "B", 16)
            pdf.set_text_color(45, 45, 94)
            pdf.cell(0, 10, clean_inline(text), ln=True)
            pdf.set_draw_color(200, 200, 220)
            pdf.line(10, pdf.get_y(), 100, pdf.get_y())
            pdf.ln(4)
            i += 1
            continue

        # H3 headings
        if line.startswith("### "):
            text = line[4:].strip()
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(58, 58, 110)
            pdf.cell(0, 8, clean_inline(text), ln=True)
            pdf.ln(2)
            i += 1
            continue

        # Tables
        if line.strip().startswith("|") and i + 1 < len(lines) and lines[i + 1].strip().startswith("|"):
            rows, end_idx = parse_table(lines, i)
            if rows:
                render_table(pdf, rows)
            i = end_idx
            continue

        # List items
        if re.match(r'^[-*] ', line.strip()):
            text = re.sub(r'^[-*] ', '', line.strip())
            text = clean_inline(text)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(40, 40, 60)
            x = pdf.get_x()
            pdf.cell(8, 6, "-", ln=False)
            pdf.multi_cell(pdf.w - 28, 6, text)
            i += 1
            continue

        # Numbered list items
        if re.match(r'^\d+\. ', line.strip()):
            match = re.match(r'^(\d+)\. (.*)', line.strip())
            if match:
                num = match.group(1)
                text = clean_inline(match.group(2))
                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(40, 40, 60)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(8, 6, f"{num}.", ln=False)
                pdf.set_font("Helvetica", "", 10)
                pdf.multi_cell(pdf.w - 28, 6, text)
            i += 1
            continue

        # Empty lines
        if not line.strip():
            pdf.ln(2)
            i += 1
            continue

        # Regular paragraphs
        text = clean_inline(line)
        if text:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(40, 40, 60)

            if pdf.get_y() + 8 > pdf.h - 25:
                pdf.add_page()

            pdf.multi_cell(0, 5.5, text)
            pdf.ln(1)

        i += 1

    # Save
    pdf.output(str(PDF_FILE))
    print(f"PDF written to {PDF_FILE}")
    print(f"Pages: {pdf.page_no()}")


if __name__ == "__main__":
    main()
