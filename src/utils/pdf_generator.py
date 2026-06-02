import re
from pathlib import Path
from fpdf import FPDF

class SecurityReportPDF(FPDF):
    def header(self):
        # Premium dark blue header bar
        self.set_fill_color(26, 73, 142)  # Dark blue
        self.rect(0, 0, 210, 20, "F")
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, "SENTINEL AI - BINARY SECURITY AUDIT REPORT", ln=True, align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


def sanitize_unicode(text: str) -> str:
    """
    Sanitizes standard Markdown text to replace unsupported Unicode characters
    with standard Latin-1/ASCII equivalents to prevent FPDF font failures.
    """
    replacements = {
        "\u2014": " - ",  # Em-dash
        "\u2013": "-",    # En-dash
        "\u201c": '"',    # Left curly double quote
        "\u201d": '"',    # Right curly double quote
        "\u2018": "'",    # Left curly single quote
        "\u2019": "'",    # Right curly single quote
        "\u2022": "*",    # Bullet point
        "\u2010": "-",    # Hyphen
        "\u2011": "-",    # Non-breaking hyphen
        "\u00a0": " ",    # Non-breaking space
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    # Fallback to ignore any remaining non-latin1 characters
    return text.encode("latin-1", "ignore").decode("latin-1")


def convert_markdown_to_pdf(markdown_text: str, pdf_path: str | Path):
    """
    Converts a Markdown-formatted vulnerability report into a beautifully styled PDF.
    Parses basic Markdown elements like Headers, Bold text, Bullet lists, and Code Blocks.
    """
    # Sanitize incoming markdown to remove unsafe unicode symbols
    markdown_text = sanitize_unicode(markdown_text)

    pdf = SecurityReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=10)
    pdf.set_text_color(51, 51, 51)  # Charcoal

    lines = markdown_text.split("\n")
    in_code_block = False
    code_content = []

    for line in lines:
        stripped = line.strip()

        # Handle Code Block delimiters
        if stripped.startswith("```"):
            if in_code_block:
                # Render code block
                pdf.set_fill_color(248, 249, 250)  # Light grey
                pdf.set_font("Courier", size=8)
                pdf.set_text_color(180, 40, 40)    # Reddish brown for code
                
                # We draw a left border line in gold to look premium
                current_x = pdf.get_x()
                current_y = pdf.get_y()
                
                # Multi-line cell for code
                code_text = "\n".join(code_content)
                pdf.multi_cell(0, 4, code_text, border=0, fill=True)
                
                # Draw gold border line
                pdf.set_draw_color(255, 193, 7)  # Gold
                pdf.set_line_width(0.8)
                pdf.line(current_x, current_y, current_x, pdf.get_y())
                
                pdf.ln(4)
                
                # Reset fonts and state
                in_code_block = False
                code_content = []
            else:
                in_code_block = True
            continue

        if in_code_block:
            code_content.append(line)
            continue

        # Header 1 (e.g. # Title)
        if stripped.startswith("# "):
            title = stripped[2:]
            pdf.ln(5)
            pdf.set_font("Helvetica", "B", 18)
            pdf.set_text_color(220, 53, 69)  # Red accent
            pdf.cell(0, 10, title, ln=True)
            pdf.set_draw_color(220, 53, 69)
            pdf.set_line_width(0.5)
            pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
            pdf.ln(4)
            continue

        # Header 2 (e.g. ## Section)
        if stripped.startswith("## "):
            section = stripped[3:]
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(52, 58, 64)  # Dark grey
            pdf.cell(0, 8, section, ln=True)
            pdf.ln(2)
            continue

        # Header 3 (e.g. ### Sub-section)
        if stripped.startswith("### "):
            sub = stripped[4:]
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(100, 110, 120)
            pdf.cell(0, 6, sub, ln=True)
            pdf.ln(1)
            continue

        # Bullet lists (e.g. - item or * item)
        if stripped.startswith("- ") or stripped.startswith("* "):
            item = stripped[2:]
            pdf.set_font("Helvetica", size=10)
            pdf.set_text_color(51, 51, 51)
            pdf.cell(5, 5, chr(149), ln=False)  # Bullet character
            
            # Simple parse bold in bullets
            parts = re.split(r"(\*\*.*?\*\*)", item)
            for part in parts:
                if part.startswith("**") and part.endswith("**"):
                    pdf.set_font("Helvetica", "B", 10)
                    pdf.write(5, part[2:-2])
                else:
                    pdf.set_font("Helvetica", "", 10)
                    pdf.write(5, part)
            pdf.ln(6)
            continue

        # Regular paragraph text (handles bold parser)
        if stripped:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(51, 51, 51)
            
            # Parse bold **bold text**
            parts = re.split(r"(\*\*.*?\*\*)", line)
            for part in parts:
                if part.startswith("**") and part.endswith("**"):
                    pdf.set_font("Helvetica", "B", 10)
                    pdf.write(5, part[2:-2])
                else:
                    pdf.set_font("Helvetica", "", 10)
                    pdf.write(5, part)
            pdf.ln(6)
        else:
            pdf.ln(2)

    # Save PDF
    pdf.output(str(pdf_path))
