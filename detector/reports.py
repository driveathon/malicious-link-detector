from fpdf import FPDF
import datetime
import os
import json

class InstitutionalReport(FPDF):
    def header(self):
        # Corporate Header
        self.set_fill_color(10, 20, 40) # FinLink Navy
        self.rect(0, 0, 210, 40, 'F')
        
        self.set_font('helvetica', 'B', 24)
        self.set_text_color(255, 255, 255)
        self.cell(0, 20, 'FINLINK | SECURITY ANALYSIS', ln=True, align='C')
        
        self.set_font('helvetica', 'B', 10)
        self.set_text_color(100, 150, 255)
        self.cell(0, 0, 'CORPORATE THREAT INTELLIGENCE DOSSIER', ln=True, align='C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} - Verified by Antigravity AI Security Node - {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}', align='C')

def generate_url_report(url, report_data, output_path):
    pdf = InstitutionalReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # 1. Executive Summary
    pdf.set_font('helvetica', 'B', 16)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(0, 10, 'EXECUTIVE SUMMARY', ln=True)
    pdf.ln(2)
    
    is_malicious = report_data.get('is_malicious', False)
    status = "THREAT DETECTED" if is_malicious else "CLEARED / SECURE"
    status_color = (200, 0, 0) if is_malicious else (0, 150, 50)
    
    pdf.set_font('helvetica', 'B', 12)
    pdf.set_text_color(*status_color)
    pdf.cell(40, 10, 'STATUS:', ln=False)
    pdf.set_font('helvetica', '', 12)
    pdf.cell(0, 10, status, ln=True)
    
    pdf.set_text_color(40, 40, 40)
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 8, 'TARGET URL:', ln=False)
    pdf.set_font('helvetica', '', 9)
    pdf.multi_cell(0, 8, url)
    
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 8, 'FINAL TARGET:', ln=False)
    pdf.set_font('helvetica', '', 9)
    pdf.multi_cell(0, 8, report_data.get('final_url', url))
    
    pdf.ln(5)
    
    # 2. Risk Indicators
    if is_malicious:
        pdf.set_fill_color(255, 240, 240)
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, 'SECURITY VIOLATIONS', ln=True, fill=True)
        pdf.set_font('helvetica', '', 10)
        for reason in report_data.get('reasons', []):
            pdf.multi_cell(0, 8, f"- {reason}")
        pdf.ln(5)

    # 3. Technical Intelligence
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, 'TECHNICAL INTELLIGENCE', ln=True)
    pdf.ln(2)
    
    # Grid data
    data = [
        ["Attribute", "Value"],
        ["Domain Entropy", f"{report_data.get('entropy', 0):.2f}/8.0"],
        ["Jurisdiction", f"{report_data.get('geo', {}).get('country', 'Unknown')}"],
        ["ISP Provider", f"{report_data.get('geo', {}).get('isp', 'Unknown')}"],
        ["IP Address", f"{report_data.get('geo', {}).get('ip', 'Unknown')}"],
        ["SSL Status", "Valid TLS" if report_data.get('ssl', {}).get('has_https') else "No Encryption"],
    ]
    
    pdf.set_font('helvetica', 'B', 10)
    for row in data:
        pdf.cell(60, 8, row[0], border=1)
        pdf.set_font('helvetica', '', 10)
        pdf.cell(0, 8, row[1], border=1, ln=True)
        pdf.set_font('helvetica', 'B', 10)
    
    pdf.ln(10)
    
    # 4. Evidence Logs (Screenshot)
    screenshot_path = report_data.get('screenshot_path')
    if screenshot_path and os.path.exists(screenshot_path):
        pdf.add_page()
        pdf.set_font('helvetica', 'B', 16)
        pdf.cell(0, 10, 'OPTICAL EVIDENCE LOG', ln=True)
        pdf.ln(5)
        # Try to fit image
        try:
            pdf.image(screenshot_path, x=10, y=None, w=190)
        except Exception as e:
            pdf.set_font('helvetica', 'I', 10)
            pdf.cell(0, 10, f'Evidence attachment failed: {str(e)}', ln=True)

    pdf.output(output_path)
    return output_path
