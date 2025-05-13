"""
Packet Analyzer Module for NebulaGuard IDS
Analyzes network packets to identify protocols and security threats
"""

import logging
import re
import socket
from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw, Ether
from scapy.layers.http import HTTP
from collections import defaultdict

# Configure logging
logger = logging.getLogger(__name__)

class PacketAnalyzer:
    """Analyzes network packets to identify protocols and potential threats"""
    
    def __init__(self):
        """Initialize the packet analyzer with traffic tracking dictionaries"""
        # Initialize counters and tracking lists
        self.connection_attempts = defaultdict(int)  # Track connection attempts by source IP
        self.port_scan_threshold = 15  # Number of different ports to trigger port scan detection
        self.source_ports = defaultdict(set)  # Track unique ports by source IP
        self.failed_logins = defaultdict(int)  # Track failed login attempts
        self.known_threats = self._load_threat_signatures()
        
        logger.debug("PacketAnalyzer initialized")
    
    def analyze_packet(self, packet):
        """
        Analyze a network packet to extract information and detect threats
        
        Args:
            packet: Captured network packet (Scapy packet object)
            
        Returns:
            dict: Packet information including protocol, IPs, and potential threats
        """
        packet_info = {
            'timestamp': None,
            'source_mac': None,
            'destination_mac': None,
            'source_ip': None,
            'destination_ip': None,
            'protocol': 'other',
            'source_port': None,
            'destination_port': None,
            'length': len(packet),
            'suspicious': False,
            'suspicious_reason': None,
            'severity': 'low'
        }
        
        try:
            # Extract Ethernet layer information if available
            if Ether in packet:
                packet_info['source_mac'] = packet[Ether].src
                packet_info['destination_mac'] = packet[Ether].dst
            
            # Extract IP layer information if available
            if IP in packet:
                packet_info['source_ip'] = packet[IP].src
                packet_info['destination_ip'] = packet[IP].dst
                
                # Track for potential port scanning
                src_ip = packet[IP].src
                
                # TCP protocol analysis
                if TCP in packet:
                    packet_info['source_port'] = packet[TCP].sport
                    packet_info['destination_port'] = packet[TCP].dport
                    
                    # Add source port to the set of ports used by this IP
                    self.source_ports[src_ip].add(packet[TCP].dport)
                    
                    # Check for port scanning
                    if len(self.source_ports[src_ip]) > self.port_scan_threshold:
                        packet_info['suspicious'] = True
                        packet_info['suspicious_reason'] = f"Potential port scanning detected from {src_ip}"
                        packet_info['severity'] = 'medium'
                        
                        # Reset tracked ports after detection to prevent continuous alerts
                        if len(self.source_ports[src_ip]) > 30:
                            self.source_ports[src_ip].clear()
                    
                    # Identify protocol based on port
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        packet_info['protocol'] = 'http'
                        
                        # Analyze HTTP content if Raw layer exists
                        if Raw in packet and self._contains_http_methods(packet[Raw].load):
                            http_content = packet[Raw].load.decode('utf-8', 'ignore')
                            
                            # Check for SQL injection
                            if self._check_sql_injection(http_content):
                                packet_info['suspicious'] = True
                                packet_info['suspicious_reason'] = f"Potential SQL injection attempt detected in HTTP request from {src_ip}"
                                packet_info['severity'] = 'high'
                            
                            # Check for XSS
                            elif self._check_xss(http_content):
                                packet_info['suspicious'] = True
                                packet_info['suspicious_reason'] = f"Potential XSS attempt detected in HTTP request from {src_ip}"
                                packet_info['severity'] = 'high'
                    
                    elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        packet_info['protocol'] = 'https'
                    
                    elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                        packet_info['protocol'] = 'ssh'
                        
                        # Increment connection attempts for this IP if it's a new connection
                        if packet[TCP].flags & 0x02:  # SYN flag set
                            self.connection_attempts[src_ip] += 1
                            
                            # Check for brute force attempts
                            if self.connection_attempts[src_ip] > 10:
                                packet_info['suspicious'] = True
                                packet_info['suspicious_reason'] = f"Potential SSH brute force attempt from {src_ip}"
                                packet_info['severity'] = 'high'
                    
                    elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                        packet_info['protocol'] = 'ftp'
                    
                    elif packet[TCP].dport == 25 or packet[TCP].sport == 25:
                        packet_info['protocol'] = 'smtp'
                
                # UDP protocol analysis
                elif UDP in packet:
                    packet_info['source_port'] = packet[UDP].sport
                    packet_info['destination_port'] = packet[UDP].dport
                    
                    # DNS analysis
                    if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                        packet_info['protocol'] = 'dns'
                        
                        # Check for DNS tunneling or exfiltration (very long domain names)
                        if DNS in packet and packet.haslayer(DNS) and packet[DNS].qd:
                            try:
                                query = packet[DNS].qd.qname.decode('utf-8')
                                if len(query) > 100:  # Suspicious long DNS query
                                    packet_info['suspicious'] = True
                                    packet_info['suspicious_reason'] = f"Potential DNS tunneling detected (long query: {query[:50]}...)"
                                    packet_info['severity'] = 'medium'
                            except:
                                pass
                
                # ICMP analysis
                elif ICMP in packet:
                    packet_info['protocol'] = 'icmp'
                    
                    # Check for ICMP flood (DoS)
                    self.connection_attempts[src_ip] += 1
                    if self.connection_attempts[src_ip] > 20:
                        packet_info['suspicious'] = True
                        packet_info['suspicious_reason'] = f"Potential ICMP flooding from {src_ip}"
                        packet_info['severity'] = 'medium'
                
                # Check packet against known threat signatures
                for signature in self.known_threats:
                    if Raw in packet:
                        payload = str(packet[Raw].load)
                        if signature['pattern'] in payload:
                            packet_info['suspicious'] = True
                            packet_info['suspicious_reason'] = signature['description']
                            packet_info['severity'] = signature['severity']
            
            return packet_info
        
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
            return packet_info
    
    def _load_threat_signatures(self):
        """
        Load threat signatures for detection
        In a real system, these would be loaded from a database or file
        
        Returns:
            list: List of threat signature dictionaries
        """
        # Sample threat signatures
        return [
            {
                'pattern': 'cmd.exe',
                'description': 'Potential Windows command execution',
                'severity': 'high'
            },
            {
                'pattern': '/bin/sh',
                'description': 'Potential Unix shell command',
                'severity': 'high'
            },
            {
                'pattern': 'eval(',
                'description': 'Potential code injection',
                'severity': 'high'
            },
            {
                'pattern': 'default_password',
                'description': 'Default credential usage detected',
                'severity': 'medium'
            }
        ]
    
    def _contains_http_methods(self, data):
        """
        Check if data contains HTTP methods to identify HTTP traffic
        
        Args:
            data: Raw packet data
            
        Returns:
            bool: True if HTTP methods found, False otherwise
        """
        try:
            data_str = data.decode('utf-8', 'ignore')
            http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
            return any(method in data_str[:20] for method in http_methods)
        except:
            return False
    
    def _check_sql_injection(self, content):
        """
        Check for SQL injection patterns in HTTP content
        
        Args:
            content: HTTP content string
            
        Returns:
            bool: True if SQL injection detected, False otherwise
        """
        sql_patterns = [
            r"'--",
            r"';--",
            r"'; drop table",
            r"'; select ",
            r"union select",
            r"1=1--",
            r"or 1=1",
            r"' OR '1'='1",
            r"' OR 'x'='x"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def _check_xss(self, content):
        """
        Check for XSS (Cross-Site Scripting) patterns in HTTP content
        
        Args:
            content: HTTP content string
            
        Returns:
            bool: True if XSS detected, False otherwise
        """
        xss_patterns = [
            r"<script",
            r"javascript:",
            r"onload=",
            r"onerror=",
            r"onclick=",
            r"onmouseover=",
            r"eval\(",
            r"document\.cookie",
            r"alert\(",
            r"String\.fromCharCode"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def reset_counters(self):
        """Reset all tracking counters and dictionaries"""
        self.connection_attempts.clear()
        self.source_ports.clear()
        self.failed_logins.clear()
        logger.debug("Packet analyzer counters reset")
