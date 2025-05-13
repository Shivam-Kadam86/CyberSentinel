import os
import json
import logging
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, send_file

# Import custom modules
from modules.network_monitor import NetworkMonitor
from modules.packet_analyzer import PacketAnalyzer
from modules.pdf_generator import generate_pdf_report
from modules.email_sender import send_email
from modules.utils import sanitize_input

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Initialize global variables
monitor_thread = None
is_monitoring = False
traffic_data = {
    'http': 0,
    'https': 0,
    'dns': 0,
    'ssh': 0,
    'ftp': 0,
    'smtp': 0,
    'other': 0
}
incidents = []
packets_captured = []

# Initialize network monitor and packet analyzer
network_monitor = NetworkMonitor()
packet_analyzer = PacketAnalyzer()

@app.route('/')
def index():
    """Render the main dashboard page."""
    return render_template('index.html')

@app.route('/api/monitor/start', methods=['POST'])
def start_monitoring():
    """Start network monitoring in a background thread."""
    global monitor_thread, is_monitoring
    
    if not is_monitoring:
        is_monitoring = True
        
        # Clear previous data
        traffic_data.update({k: 0 for k in traffic_data})
        incidents.clear()
        packets_captured.clear()
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=background_monitoring)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        logger.info("Network monitoring started")
        return jsonify({"status": "success", "message": "Monitoring started"})
    
    return jsonify({"status": "warning", "message": "Monitoring already active"})

@app.route('/api/monitor/stop', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring."""
    global is_monitoring
    
    if is_monitoring:
        is_monitoring = False
        logger.info("Network monitoring stopped")
        return jsonify({"status": "success", "message": "Monitoring stopped"})
    
    return jsonify({"status": "warning", "message": "Monitoring is not active"})

@app.route('/api/traffic/stats', methods=['GET'])
def get_traffic_stats():
    """Return current traffic statistics data."""
    return jsonify({
        "traffic_data": traffic_data,
        "incidents": incidents,
        "total_packets": sum(traffic_data.values()),
        "monitoring": is_monitoring
    })

@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    """Generate a PDF report of monitoring statistics."""
    try:
        report_path = generate_pdf_report(
            traffic_data=traffic_data,
            incidents=incidents,
            captured_packets=packets_captured
        )
        
        session['last_report_path'] = report_path
        return jsonify({
            "status": "success", 
            "message": "Report generated successfully",
            "report_path": report_path
        })
    
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({"status": "error", "message": f"Failed to generate report: {str(e)}"})

@app.route('/api/report/download', methods=['GET'])
def download_report():
    """Download the last generated PDF report."""
    report_path = session.get('last_report_path')
    
    if report_path and os.path.exists(report_path):
        return send_file(
            report_path,
            as_attachment=True,
            download_name=f"IDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
    else:
        return jsonify({"status": "error", "message": "No report available for download"})

@app.route('/api/report/email', methods=['POST'])
def email_report():
    """Send the last generated PDF report via email."""
    report_path = session.get('last_report_path')
    
    if not report_path or not os.path.exists(report_path):
        return jsonify({"status": "error", "message": "No report available to send"})
    
    # Get email parameters from request
    data = request.json
    recipient = sanitize_input(data.get('recipient', ''))
    subject = sanitize_input(data.get('subject', 'IDS Monitoring Report'))
    message = sanitize_input(data.get('message', 'Please find attached the IDS monitoring report.'))
    
    if not recipient:
        return jsonify({"status": "error", "message": "Recipient email is required"})
    
    try:
        send_email(recipient, subject, message, report_path)
        return jsonify({"status": "success", "message": f"Report sent to {recipient}"})
    
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        return jsonify({"status": "error", "message": f"Failed to send email: {str(e)}"})

def background_monitoring():
    """Background thread function for network monitoring."""
    global traffic_data, incidents, packets_captured
    
    logger.info("Background monitoring thread started")
    
    while is_monitoring:
        try:
            # Capture a batch of packets
            new_packets = network_monitor.capture_packets(timeout=2, count=10)
            
            if new_packets:
                # Process captured packets
                for packet in new_packets:
                    packet_info = packet_analyzer.analyze_packet(packet)
                    
                    # Update traffic statistics
                    protocol = packet_info.get('protocol', 'other').lower()
                    if protocol in traffic_data:
                        traffic_data[protocol] += 1
                    else:
                        traffic_data['other'] += 1
                    
                    # Check for potential incidents/alerts
                    if packet_info.get('suspicious', False):
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        incident = {
                            'timestamp': timestamp,
                            'source_ip': packet_info.get('source_ip', 'unknown'),
                            'destination_ip': packet_info.get('destination_ip', 'unknown'),
                            'protocol': protocol,
                            'reason': packet_info.get('suspicious_reason', 'Unknown suspicious activity'),
                            'severity': packet_info.get('severity', 'medium')
                        }
                        incidents.append(incident)
                    
                    # Add to captured packets list (limited to last 100 for memory management)
                    packets_captured.append(packet_info)
                    if len(packets_captured) > 100:
                        packets_captured.pop(0)
        
        except Exception as e:
            logger.error(f"Error in monitoring thread: {e}")
    
    logger.info("Background monitoring thread stopped")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
