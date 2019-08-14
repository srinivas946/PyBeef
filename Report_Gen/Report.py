from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import landscape, letter

class PDF_Report:

    def __init__(self, filename):
        self.doc = SimpleDocTemplate(filename)

    def index_page(self): pass

    def create_text(self, text, style_type=None, font_size=None, font_name=None, text_color=None):
        if style_type is None: style_type = 'BodyText'
        styles = getSampleStyleSheet()[style_type]
        if font_size is not None: styles.fontSize = font_size
        if text_color is not None: styles.textColor = text_color
        if font_name is not None: styles.fontName = font_name
        para = Paragraph(text, styles)
        return para

    def create_table(self, data, col_width=None):
        t = Table(data, col_width)
        t.setStyle(TableStyle([('BACKGROUND', (0, 0), (len(data[0]), 0), colors.lavender),
                               ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                               ('BOX', (0, 0), (-1, -1), 0.25, colors.black)]))
        return t

    def apply_page_break(self):
        return PageBreak()

    def save_pdf(self, elements):
        self.doc.build(elements)


