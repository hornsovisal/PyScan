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

# Base Report Manager (Abstract Base Class)
class ReportManager(ABC):
    """Base class for all report managers - demonstrates inheritance"""
    
    def __init__(self, output_dir='reports'):
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
    
    def __init__(self, output_dir='reports'):
        super().__init__(output_dir)
        self.scanner = HostScanner()
    
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
    
    def display_summary(self):
        """Display summary - polymorphic implementation"""
        reachable = [d for d in self.data if d['status'] == 'Reachable']
        unreachable = [d for d in self.data if d['status'] == 'Unreachable']
        
        print(f"\n{'='*60}")
        print(f"HOST DISCOVERY SUMMARY")
        print(f"{'='*60}")
        print(f"Total Hosts Scanned: {len(self.data)}")
        print(f"Reachable Hosts: {len(reachable)}")
        print(f"Unreachable Hosts: {len(unreachable)}")
        print(f"{'='*60}\n")
        
        if reachable:
            print(f"{'IP Address':<15} {'Hostname':<25} {'Open Ports':<20}")
            print("-" * 60)
            for host in reachable:
                print(f"{host['ip']:<15} {host['hostname']:<25} {host['ports']:<20}")
    
    def generate_report(self, filename=None):
        """Generate host discovery report in DOCX format"""
        if not filename:
            filename = self._get_filename('host_discovery_report', 'docx')
        
        filepath = os.path.join(self.output_dir, filename)
        reachable = [d for d in self.data if d['status'] == 'Reachable']
        unreachable = [d for d in self.data if d['status'] == 'Unreachable']
        
        # Create Word document
        doc = Document()
        
        # Title and Header
        self._create_docx_header(doc, 'HOST DISCOVERY SCAN REPORT')
        
        # Executive Summary Section
        doc.add_heading('Executive Summary', level=1)
        summary_table = doc.add_table(rows=4, cols=2)
        summary_table.style = 'Light Grid Accent 1'
        
        summary_data = [
            ('Total Hosts Scanned', str(len(self.data))),
            ('Reachable Hosts', f"{len(reachable)} ({len(reachable)/len(self.data)*100 if self.data else 0:.1f}%)"),
            ('Unreachable Hosts', f"{len(unreachable)} ({len(unreachable)/len(self.data)*100 if self.data else 0:.1f}%)"),
            ('Scan Method', self.data[0]['method'] if self.data else 'N/A')
        ]
        
        for idx, (label, value) in enumerate(summary_data):
            summary_table.rows[idx].cells[0].text = label
            summary_table.rows[idx].cells[1].text = value
        
        doc.add_paragraph()
        
        # Reachable Hosts Details
        if reachable:
            doc.add_heading('Reachable Hosts - Detailed Findings', level=1)
            
            for idx, host in enumerate(reachable, 1):
                para = doc.add_paragraph()
                para.add_run(f"[{idx}] {host['ip']}").bold = True
                
                details_table = doc.add_table(rows=4, cols=2)
                details_table.style = 'Light List Accent 1'
                details_table.rows[0].cells[0].text = 'Hostname'
                details_table.rows[0].cells[1].text = host['hostname']
                details_table.rows[1].cells[0].text = 'Status'
                details_table.rows[1].cells[1].text = host['status']
                details_table.rows[2].cells[0].text = 'Open Ports'
                details_table.rows[2].cells[1].text = host['ports']
                details_table.rows[3].cells[0].text = 'Method'
                details_table.rows[3].cells[1].text = host['method']
                
                doc.add_paragraph()
        
        # Complete Scan Results Table
        doc.add_heading('Complete Scan Results', level=1)
        
        results_table = doc.add_table(rows=len(self.data) + 1, cols=4)
        results_table.style = 'Light Grid Accent 1'
        
        # Header row
        header_cells = results_table.rows[0].cells
        header_cells[0].text = 'IP Address'
        header_cells[1].text = 'Status'
        header_cells[2].text = 'Hostname'
        header_cells[3].text = 'Open Ports'
        
        # Data rows
        for idx, host in enumerate(self.data, 1):
            row_cells = results_table.rows[idx].cells
            row_cells[0].text = host['ip']
            row_cells[1].text = host['status']
            row_cells[2].text = host['hostname']
            row_cells[3].text = host['ports']
        
        # Save document
        doc.save(filepath)
        print(f"✓ DOCX Report saved to: {filepath}")
        return filepath

# # Port Scan Report Manager (Inheritance)
# class PortReportManager(ReportManager):
#     """Manages port scanning reports - inherits from ReportManager"""
    
#     def __init__(self, output_dir='reports'):
#         super().__init__(output_dir)
#         self.scanner = HostScanner()
#         self.port_info = self._load_port_info()
  

# Usage Example
if __name__ == "__main__":
    # Example 1: Using HostScanner directly, then generate report from cache
    scanner = HostScanner()
    sample_range = scanner.icmp.generate_ip_range("172.23.3.1", "172.23.3.254")
    
    # Scan and display
    scanner.display(sample_range, method='auto')
    
    # Generate report from cached results (NO RE-SCANNING)
    host_report = HostReportManager()
    host_report.scanner = scanner  # Use the same scanner with cached results
    host_report.load_from_cached_scan()  # Load from cache
    host_report.generate_report()
    
    print("\n✓ Efficient workflow: Scanned once, displayed and saved results without re-scanning")
    
    # Example 2: Alternative - scan directly through report manager
    # host_report = HostReportManager()
    # ip_range = host_report.scanner.icmp.generate_ip_range("192.168.1.1", "192.168.1.10")
    # host_report.scan_and_add(ip_range, method='auto')
    # host_report.display_summary()
    # host_report.generate_report()
    
