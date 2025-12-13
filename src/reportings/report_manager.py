# Reporting System with OOP Inheritance
import os
import json
from datetime import datetime
from abc import ABC, abstractmethod
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
from host_discovery.host_discovery import HostScanner
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

# Base Report Manager (Abstract Base Class)
class ReportManager(ABC):
    """Base class for all report managers - demonstrates inheritance"""
    
    def __init__(self, output_dir='reports/host_scanner'):
        self.output_dir = output_dir
        self.data = []
        self._ensure_directory()
    
    def _ensure_directory(self):
        """Encapsulation: private method to create reports directory"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def add_data(self, data_item):
        """Add data to the report"""
        self.data.append(data_item)
    
    def clear_data(self):
        """Clear all collected data"""
        self.data = []
    
    @abstractmethod
    def generate_report(self, filename=None):
        """Abstract method - must be implemented by subclasses (polymorphism)"""
        pass
    
    @abstractmethod
    def display_summary(self):
        """Abstract method - display summary of data"""
        pass
    
    def _get_filename(self, prefix, extension='txt'):
        """Protected method to generate timestamped filename"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{prefix}_{timestamp}.{extension}"
    
    def _create_docx_header(self, doc, title):
        """Create document header with title"""
        heading = doc.add_heading(title, level=0)
        heading.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        # Add metadata
        para = doc.add_paragraph()
        para.add_run(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}").bold = True
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_paragraph()  # Spacer

# Host Discovery Report Manager (Inheritance)
class HostReportManager(ReportManager):
    """Manages host discovery reports - inherits from ReportManager"""
    
    def __init__(self, output_dir='reports/host_scanner'):
        super().__init__(output_dir)
        self.scanner = HostScanner()
        self.port_database = self._load_port_database()
    
    def _load_port_database(self):
        """Load port information from config/default_ports.json with risk levels"""
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(current_dir))
            
            if not os.path.exists(os.path.join(project_root, "config")):
                project_root = os.getcwd()
                while project_root != "/" and not os.path.exists(os.path.join(project_root, "config")):
                    project_root = os.path.dirname(project_root)
            
            config_path = os.path.join(project_root, "config/default_ports.json")
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Build database with risk levels
            port_db = {}
            risk_mapping = {
                'FTP': 'High',
                'Telnet': 'High',
                'SMB': 'High',
                'RDP': 'High',
                'NetBIOS': 'High',
                'SSH': 'Medium',
                'SMTP': 'Medium',
                'HTTP': 'Medium',
                'POP3': 'Medium',
                'IMAP': 'Medium',
                'HTTP-Proxy': 'Medium',
                'HTTPS': 'Low',
                'DNS': 'Low'
            }
            
            for port_info in data.get('common_ports', []):
                port = str(port_info['port'])
                service = port_info['service']
                description = port_info['description']
                risk = risk_mapping.get(service, 'Medium')
                port_db[port] = (service, risk, description)
            
            return port_db
        except Exception as e:
            # Fallback to basic database
            return {
                '21': ('FTP', 'High', 'Transmits credentials in plain text'),
                '22': ('SSH', 'Medium', 'Remote access service'),
                '80': ('HTTP', 'Medium', 'Unencrypted web traffic'),
                '443': ('HTTPS', 'Low', 'Encrypted web service')
            }
    
    def scan_and_add(self, ip_range, method='auto', max_workers=50, alive_only=False):
        """Scan IP range and add results to report data"""
        # Perform scan once and cache results
        results = self.scanner.scan(ip_range, method=method, max_workers=max_workers, alive_only=alive_only, show_progress=True)
        
        # Convert cached results to report format
        for result in results:
            ip, status, identity, ping_time, mac, ports = result
            self.add_data({
                'ip': ip,
                'status': 'Reachable' if status == 'Alive' else 'Unreachable',
                'hostname': identity,
                'ports': ports,
                'method': method.upper()
            })
    
    def load_from_cached_scan(self):
        """Load data from scanner's cached results without re-scanning"""
        results = self.scanner.get_cached_results()
        self.clear_data()  # Clear old data
        
        for result in results:
            ip, status, identity, ping_time, mac, ports = result
            self.add_data({
                'ip': ip,
                'status': 'Reachable' if status == 'Alive' else 'Unreachable',
                'hostname': identity,
                'ports': ports,
                'method': 'CACHED'
            })
    
    def _set_cell_background(self, cell, color):
        """Set cell background color"""
        shading_elm = OxmlElement('w:shd')
        shading_elm.set(qn('w:fill'), color)
        cell._element.get_or_add_tcPr().append(shading_elm)
    
    def _add_risk_indicator(self, doc, level):
        """Add colored risk indicator"""
        para = doc.add_paragraph()
        run = para.add_run(f"● {level} Risk: ")
        run.font.size = Pt(10)
        
        if level == "High":
            run.font.color.rgb = RGBColor(255, 0, 0)
        elif level == "Medium":
            run.font.color.rgb = RGBColor(255, 165, 0)
        else:
            run.font.color.rgb = RGBColor(0, 128, 0)
        
        return para
    
    def generate_report(self, filename=None, customer_name="<Company / Client Name>", 
                       network_range="<e.g. 192.168.1.0/24>", project_by="<Your Name / Team Name>"):
        """Generate professional host discovery report matching the template"""
        if not filename:
            filename = self._get_filename('host_discovery_report', 'docx')
        
        filepath = os.path.join(self.output_dir, filename)
        reachable = [d for d in self.data if d['status'] == 'Reachable']
        unreachable = [d for d in self.data if d['status'] == 'Unreachable']
        
        # Create Word document
        doc = Document()
        
        # ===== TITLE =====
        title = doc.add_heading('NETWORK SCANNING - Host Discovery REPORT', level=0)
        title.alignment = WD_ALIGN_PARAGRAPH.LEFT
        title.runs[0].font.size = Pt(18)
        title.runs[0].font.bold = True
        title.runs[0].font.color.rgb = RGBColor(0, 51, 102)  # Dark blue
        title.runs[0].font.name = 'Arial'
        
        # ===== METADATA =====
        metadata = [
            f"Customer Name: {customer_name}",
            f"Network Range Scanned: {network_range}",
            f"Scan Date: {datetime.now().strftime('%d-%b-%Y')}",
            f"Report Generated: {datetime.now().strftime('%d-%b-%Y %H:%M:%S')}",
            f"Project By: {project_by}"
        ]
        
        for text in metadata:
            para = doc.add_paragraph()
            if ':' in text:
                label, value = text.split(':', 1)
                run_label = para.add_run(label + ':')
                run_label.font.bold = True
                run_label.font.size = Pt(11)
                run_label.font.name = 'Arial'
                run_value = para.add_run(value)
                run_value.font.size = Pt(11)
                run_value.font.name = 'Arial'
            else:
                run = para.add_run(text)
                run.font.size = Pt(11)
                run.font.name = 'Arial'
        
        doc.add_paragraph()
        
        # ===== 1. EXECUTIVE SUMMARY =====
        heading1 = doc.add_heading('1. EXECUTIVE SUMMARY', level=1)
        heading1.runs[0].font.size = Pt(14)
        heading1.runs[0].font.color.rgb = RGBColor(0, 51, 102)
        heading1.runs[0].font.name = 'Arial'
        
        para = doc.add_paragraph(
            f"An automated network host discovery and port scanning assessment was conducted using a "
            f"Python-based security tool. The scan allowed rapid identification of active hosts, "
            f"open ports, and exposed services across the target network. The goal of this assessment "
            f"was to evaluate security risks and provide recommendations for strengthening network defenses."
        )
        para.runs[0].font.size = Pt(11)
        para.runs[0].font.name = 'Arial'
        para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        doc.add_paragraph()
        
        # ===== 2. SCAN OBJECTIVE =====
        heading2 = doc.add_heading('2. SCAN OBJECTIVE', level=1)
        heading2.runs[0].font.size = Pt(14)
        heading2.runs[0].font.color.rgb = RGBColor(0, 51, 102)
        heading2.runs[0].font.name = 'Arial'
        
        objectives = [
            "Automatically discover live hosts in the target network",
            "Identify open ports and running services",
            "Map network topology and device connectivity",
            "Detect potential security exposures",
            "Generate a structured security report"
        ]
        for obj in objectives:
            p = doc.add_paragraph(f"● {obj}", style='List Bullet')
            p.runs[0].font.size = Pt(11)
            p.runs[0].font.name = 'Arial'
        doc.add_paragraph()
        
        # ===== 3. SCAN METHODOLOGY =====
        heading3 = doc.add_heading('3. SCAN METHODOLOGY (AUTOMATED)', level=1)
        heading3.runs[0].font.size = Pt(14)
        heading3.runs[0].font.color.rgb = RGBColor(0, 51, 102)
        heading3.runs[0].font.name = 'Arial'
        
        methodology = [
            "The scan was executed using a Python-based automation script",
            "ICMP and TCP techniques were used for host discovery",
            "Multi-threaded scanning enabled fast network enumeration",
            "Service detection was carried out using known port-to-service mapping",
            "Risk levels were automatically assigned based on open ports and service data",
            "The final report was generated from the automated scan output"
        ]
        for method in methodology:
            p = doc.add_paragraph(f"● {method}", style='List Bullet')
            p.runs[0].font.size = Pt(11)
            p.runs[0].font.name = 'Arial'
        doc.add_paragraph()
        
        # ===== 4. DETAILED PORT & HOST REPORT =====
        heading4 = doc.add_heading('4. DETAILED PORT & HOST REPORT', level=1)
        heading4.runs[0].font.size = Pt(14)
        heading4.runs[0].font.color.rgb = RGBColor(0, 51, 102)
        heading4.runs[0].font.name = 'Arial'
        
        # Summary table
        table = doc.add_table(rows=len(reachable) + 1, cols=5)
        table.style = 'Light Grid Accent 1'
        
        # Header
        headers = ['Host Name', 'IP Address', 'Open Ports', 'Services Running', 'Risk Level']
        for idx, header in enumerate(headers):
            cell = table.rows[0].cells[idx]
            cell.text = header
            self._set_cell_background(cell, '4472C4')  # Professional blue
            # Style header text
            for paragraph in cell.paragraphs:
                for run in paragraph.runs:
                    run.font.bold = True
                    run.font.size = Pt(11)
                    run.font.color.rgb = RGBColor(255, 255, 255)  # White text
                    run.font.name = 'Arial'
        
        # Data rows
        for idx, host in enumerate(reachable, 1):
            cells = table.rows[idx].cells
            
            # Determine host name
            host_name = f"PC-{idx:02d}" if host['hostname'] == host['ip'] else host['hostname']
            cells[0].text = host_name
            cells[1].text = host['ip']
            
            # Parse ports
            ports_list = host['ports'].split(',') if host['ports'] != 'None' else []
            cells[2].text = ', '.join(ports_list) if ports_list else 'None'
            
            # Map ports to services using loaded database
            services = []
            risk_level = "Low"
            for port in ports_list:
                port_num = port.strip()
                if port_num in self.port_database:
                    service, level, _ = self.port_database[port_num]
                    services.append(service)
                    # Determine highest risk level
                    if level == "High":
                        risk_level = "High"
                    elif level == "Medium" and risk_level != "High":
                        risk_level = "Medium"
                else:
                    services.append(f"Port-{port_num}")
            
            cells[3].text = ', '.join(services) if services else 'N/A'
            cells[4].text = risk_level
            
            # Style all cells
            for cell in cells:
                for paragraph in cell.paragraphs:
                    for run in paragraph.runs:
                        run.font.size = Pt(10)
                        run.font.name = 'Arial'
            
            # Color code risk level
            if risk_level == "High":
                self._set_cell_background(cells[4], 'FF6B6B')
                cells[4].paragraphs[0].runs[0].font.bold = True
                cells[4].paragraphs[0].runs[0].font.color.rgb = RGBColor(139, 0, 0)
            elif risk_level == "Medium":
                self._set_cell_background(cells[4], 'FFD93D')
                cells[4].paragraphs[0].runs[0].font.bold = True
                cells[4].paragraphs[0].runs[0].font.color.rgb = RGBColor(184, 134, 11)
            else:
                self._set_cell_background(cells[4], '6BCF7F')
                cells[4].paragraphs[0].runs[0].font.bold = True
                cells[4].paragraphs[0].runs[0].font.color.rgb = RGBColor(0, 100, 0)
        
        doc.add_paragraph()
        
        # Risk legend
        self._add_risk_indicator(doc, "High")
        run = doc.paragraphs[-1].add_run("Public services like FTP and SMB")
        run.font.size = Pt(10)
        run.font.name = 'Arial'
        
        self._add_risk_indicator(doc, "Medium")
        run = doc.paragraphs[-1].add_run("Web & Remote Access")
        run.font.size = Pt(10)
        run.font.name = 'Arial'
        
        self._add_risk_indicator(doc, "Low")
        run = doc.paragraphs[-1].add_run("Normal internal services")
        run.font.size = Pt(10)
        run.font.name = 'Arial'
        
        doc.add_paragraph()
        
        # ===== 5. PORT RISK CLASSIFICATION =====
        heading5 = doc.add_heading('5. Port Risk Classification', level=1)
        heading5.runs[0].font.size = Pt(14)
        heading5.runs[0].font.color.rgb = RGBColor(0, 51, 102)
        heading5.runs[0].font.name = 'Arial'
        
        # Collect all unique open ports from scan results
        all_open_ports = set()
        for host in reachable:
            if host['ports'] != 'None':
                ports_list = host['ports'].split(',')
                for port in ports_list:
                    all_open_ports.add(port.strip())
        
        # Filter to only show ports that were found
        risk_data = []
        for port in sorted(all_open_ports, key=lambda x: int(x) if x.isdigit() else 0):
            if port in self.port_database:
                service, level, reason = self.port_database[port]
                risk_data.append((port, service, level, reason))
            else:
                risk_data.append((port, 'Unknown', 'Medium', 'Unidentified service'))
        
        # Create table with dynamic rows
        if risk_data:
            risk_table = doc.add_table(rows=len(risk_data) + 1, cols=3)
            risk_table.style = 'Light Grid Accent 1'
            
            # Headers
            header_labels = ['Port', 'Service', 'Risk Level\nReason']
            for idx, label in enumerate(header_labels):
                cell = risk_table.rows[0].cells[idx]
                cell.text = label
                self._set_cell_background(cell, '4472C4')
                for paragraph in cell.paragraphs:
                    for run in paragraph.runs:
                        run.font.bold = True
                        run.font.size = Pt(11)
                        run.font.color.rgb = RGBColor(255, 255, 255)
                        run.font.name = 'Arial'
            
            # Data rows
            for idx, (port, service, level, reason) in enumerate(risk_data, 1):
                cells = risk_table.rows[idx].cells
                cells[0].text = port
                cells[1].text = service
                cells[2].text = f"{level}\n{reason}"
                
                # Style cells
                for cell in cells:
                    for paragraph in cell.paragraphs:
                        for run in paragraph.runs:
                            run.font.size = Pt(10)
                            run.font.name = 'Arial'
                
                if level == "High":
                    self._set_cell_background(cells[2], 'FF6B6B')
                    cells[2].paragraphs[0].runs[0].font.bold = True
                    cells[2].paragraphs[0].runs[0].font.color.rgb = RGBColor(139, 0, 0)
                elif level == "Medium":
                    self._set_cell_background(cells[2], 'FFD93D')
                    cells[2].paragraphs[0].runs[0].font.bold = True
                    cells[2].paragraphs[0].runs[0].font.color.rgb = RGBColor(184, 134, 11)
                else:
                    self._set_cell_background(cells[2], '6BCF7F')
                    cells[2].paragraphs[0].runs[0].font.bold = True
                    cells[2].paragraphs[0].runs[0].font.color.rgb = RGBColor(0, 100, 0)
        else:
            doc.add_paragraph("No open ports detected during scan.")
        
        # Save document
        doc.save(filepath)
        print(f"✓ Professional DOCX Report saved to: {filepath}")
        return filepath



# Usage Example
if __name__ == "__main__":
    # Example 1: Using HostScanner directly, then generate professional report from cache
    scanner = HostScanner()
    sample_range = scanner.icmp.generate_ip_range("192.168.100.1", "192.168.100.214")
    
    # Scan and display
    scanner.display(sample_range, method='auto')
    
    # Generate professional report from cached results (NO RE-SCANNING)
    host_report = HostReportManager()
    host_report.scanner = scanner  # Use the same scanner with cached results
    host_report.load_from_cached_scan()  # Load from cache
    
    # Generate report with custom metadata
    host_report.generate_report(
        customer_name="CADT Network Security Team",
        network_range="172.23.3.0/24",
        project_by="Horn Sovisal, Kuyseng Marakat, Chhit Sovathana"
    )
    
    print("\n✓ Professional report generated matching security assessment template!")

