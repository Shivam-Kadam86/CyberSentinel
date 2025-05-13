"""
PDF Generator Module for NebulaGuard IDS
Generates PDF reports of network monitoring data
"""

import os
import logging
from datetime import datetime
import tempfile
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus import Image, PageBreak
from reportlab.lib.units import inch

# Configure logging
logger = logging.getLogger(__name__)

def generate_pdf_report(traffic_data, incidents, captured_packets, output_path=None):
    """
    Generate a PDF report of the IDS monitoring data
    
    Args:
        traffic_data (dict): Dictionary of traffic statistics by protocol
        incidents (list): List of security incidents detected
        captured_packets (list): List of captured packet details
        output_path (str, optional): Path to save the generated PDF. If None, uses a temp file.
        
    Returns:
        str: Path to the generated PDF file
    """
    try:
        # Create a temp file if no output path specified
        if not output_path:
            temp_dir = tempfile.gettempdir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(temp_dir, f"nebulaGuard_report_{timestamp}.pdf")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        # Create PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        # Styles
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='Title',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#0390fc'),
            spaceAfter=12
        ))
        styles.add(ParagraphStyle(
            name='Heading2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=colors.HexColor('#7d3fe2'),
            spaceAfter=10
        ))
        styles.add(ParagraphStyle(
            name='Normal',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            spaceAfter=6
        ))
        styles.add(ParagraphStyle(
            name='Alert',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            textColor=colors.HexColor('#ff304f')
        ))
        
        # Content elements
        elements = []
        
        # Add report title
        elements.append(Paragraph("NebulaGuard IDS Security Report", styles['Title']))
        
        # Add report timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elements.append(Paragraph(f"Generated on: {timestamp}", styles['Normal']))
        elements.append(Spacer(1, 0.25 * inch))
        
        # --- Summary Section ---
        elements.append(Paragraph("1. Executive Summary", styles['Heading2']))
        
        # Summary text
        summary_text = f"""
        This report provides an analysis of network traffic monitored by NebulaGuard Intrusion Detection System. 
        During the monitoring period, a total of <b>{sum(traffic_data.values())}</b> packets were captured across 
        different protocols. The system detected <b>{len(incidents)}</b> potential security incidents that may 
        require attention.
        """
        elements.append(Paragraph(summary_text, styles['Normal']))
        elements.append(Spacer(1, 0.2 * inch))
        
        # --- Traffic Analysis Section ---
        elements.append(Paragraph("2. Traffic Analysis", styles['Heading2']))
        
        # Traffic data table
        traffic_table_data = [
            ["Protocol", "Packet Count", "Percentage"],
        ]
        
        total_packets = sum(traffic_data.values())
        for protocol, count in traffic_data.items():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            traffic_table_data.append([
                protocol.upper(),
                str(count),
                f"{percentage:.1f}%"
            ])
        
        # Add total row
        traffic_table_data.append([
            "TOTAL",
            str(total_packets),
            "100%"
        ])
        
        traffic_table = Table(traffic_table_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch])
        traffic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#111824')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#f8f9fa')),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dddddd')),
            ('ALIGN', (1, 1), (2, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(traffic_table)
        elements.append(Spacer(1, 0.3 * inch))
        
        # --- Security Incidents Section ---
        elements.append(Paragraph("3. Security Incidents", styles['Heading2']))
        
        if incidents:
            # Group incidents by severity
            incidents_by_severity = {"high": [], "medium": [], "low": []}
            for incident in incidents:
                severity = incident.get('severity', 'low')
                incidents_by_severity[severity].append(incident)
            
            # Add count information
            incident_summary = f"""
            A total of {len(incidents)} security incidents were detected during the monitoring period:
            • High Severity: {len(incidents_by_severity['high'])}
            • Medium Severity: {len(incidents_by_severity['medium'])}
            • Low Severity: {len(incidents_by_severity['low'])}
            """
            elements.append(Paragraph(incident_summary, styles['Normal']))
            elements.append(Spacer(1, 0.2 * inch))
            
            # Add detailed incidents - focus on high and medium severity
            for severity in ['high', 'medium', 'low']:
                if incidents_by_severity[severity]:
                    severity_title = severity.capitalize()
                    section_num = {'high': 1, 'medium': 2, 'low': 3}[severity]
                    elements.append(Paragraph(f"3.{section_num}. {severity_title} Severity Incidents", styles['Heading2']))
                    
                    incidents_table_data = [
                        ["Timestamp", "Source IP", "Destination IP", "Protocol", "Description"],
                    ]
                    
                    for incident in incidents_by_severity[severity]:
                        incidents_table_data.append([
                            incident.get('timestamp', 'Unknown'),
                            incident.get('source_ip', 'Unknown'),
                            incident.get('destination_ip', 'Unknown'),
                            incident.get('protocol', 'Unknown').upper(),
                            incident.get('reason', 'Unknown reason')
                        ])
                    
                    incidents_table = Table(incidents_table_data, colWidths=[1.2*inch, 1*inch, 1*inch, 0.8*inch, 2*inch])
                    incidents_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#111824')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dddddd')),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('PADDING', (0, 0), (-1, -1), 6),
                        ('WORDWRAP', (4, 1), (4, -1), True),
                    ]))
                    
                    elements.append(incidents_table)
                    elements.append(Spacer(1, 0.3 * inch))
        else:
            elements.append(Paragraph("No security incidents were detected during the monitoring period.", styles['Normal']))
            elements.append(Spacer(1, 0.3 * inch))
        
        # --- Recommendations Section ---
        elements.append(Paragraph("4. Security Recommendations", styles['Heading2']))
        
        # Generate recommendations based on incidents
        recommendations = []
        if any(incident.get('reason', '').lower().find('port scan') != -1 for incident in incidents):
            recommendations.append("• Configure firewall rules to limit port scanning from external networks")
            recommendations.append("• Implement rate limiting on connection attempts")
        
        if any(incident.get('reason', '').lower().find('brute force') != -1 for incident in incidents):
            recommendations.append("• Implement more robust password policies")
            recommendations.append("• Consider implementing multi-factor authentication")
            recommendations.append("• Set up account lockout policies to prevent brute force attacks")
        
        if any(incident.get('reason', '').lower().find('injection') != -1 for incident in incidents):
            recommendations.append("• Review web application security practices")
            recommendations.append("• Implement input validation and parametrized queries")
            recommendations.append("• Consider using a Web Application Firewall (WAF)")
        
        if any(incident.get('protocol', '').lower() == 'http' for incident in incidents):
            recommendations.append("• Consider moving HTTP services to HTTPS for better security")
            recommendations.append("• Implement HTTP security headers")
        
        # Add default recommendations if none generated from incidents
        if not recommendations:
            recommendations = [
                "• Regularly update and patch systems to mitigate vulnerabilities",
                "• Implement network segmentation to limit potential attack surfaces",
                "• Regularly audit user accounts and access privileges",
                "• Implement endpoint protection solutions",
                "• Create and maintain security monitoring and incident response procedures"
            ]
        
        # Add recommendations to document
        for recommendation in recommendations:
            elements.append(Paragraph(recommendation, styles['Normal']))
        
        elements.append(Spacer(1, 0.3 * inch))
        
        # --- Packet Sample Section ---
        if captured_packets:
            elements.append(PageBreak())
            elements.append(Paragraph("5. Packet Sample Analysis", styles['Heading2']))
            
            elements.append(Paragraph("The following table shows a sample of the most recent packets captured during monitoring:", styles['Normal']))
            elements.append(Spacer(1, 0.2 * inch))
            
            # Show only the last 20 packets to keep report manageable
            sample_packets = captured_packets[-20:]
            
            packet_table_data = [
                ["Source IP", "Destination IP", "Protocol", "Length", "Flags"],
            ]
            
            for packet in sample_packets:
                # Add flags or additional info if available
                flags = ""
                if packet.get('suspicious', False):
                    flags = "SUSPICIOUS"
                
                packet_table_data.append([
                    packet.get('source_ip', 'Unknown'),
                    packet.get('destination_ip', 'Unknown'),
                    packet.get('protocol', 'Unknown').upper(),
                    str(packet.get('length', 0)),
                    flags
                ])
            
            packet_table = Table(packet_table_data, colWidths=[1.2*inch, 1.2*inch, 0.8*inch, 0.8*inch, 1.5*inch])
            packet_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#111824')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dddddd')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('TEXTCOLOR', (4, 1), (4, -1), colors.HexColor('#ff304f')),
            ]))
            
            elements.append(packet_table)
        
        # Generate the PDF
        doc.build(elements)
        logger.info(f"PDF report generated successfully: {output_path}")
        return output_path
        
    except Exception as e:
        logger.error(f"Error generating PDF report: {e}")
        raise
