"""
Utility functions for NebulaGuard IDS
Contains helper functions used across the application
"""

import os
import re
import logging
import html
import socket
import json
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

def sanitize_input(text):
    """
    Sanitize input text to prevent injection attacks
    
    Args:
        text (str): Input text to sanitize
        
    Returns:
        str: Sanitized text
    """
    if not text:
        return ""
    
    # Convert to string if not already
    if not isinstance(text, str):
        text = str(text)
    
    # HTML escape to prevent XSS
    sanitized = html.escape(text)
    
    # Remove any control characters
    sanitized = re.sub(r'[\x00-\x1F\x7F]', '', sanitized)
    
    return sanitized

def validate_ip_address(ip):
    """
    Validate if a string is a valid IP address
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid IP address, False otherwise
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_email(email):
    """
    Validate if a string is a valid email address
    
    Args:
        email (str): Email address to validate
        
    Returns:
        bool: True if valid email address, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def get_timestamp():
    """
    Get current timestamp in formatted string
    
    Returns:
        str: Formatted timestamp
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def save_to_json(data, filename):
    """
    Save data to a JSON file
    
    Args:
        data: Data to save
        filename (str): Path to save the file
        
    Returns:
        bool: True if saved successfully, False otherwise
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
        return True
    except Exception as e:
        logger.error(f"Error saving JSON file: {e}")
        return False

def load_from_json(filename):
    """
    Load data from a JSON file
    
    Args:
        filename (str): Path to the JSON file
        
    Returns:
        dict/list: Loaded data, or None if error
    """
    try:
        if not os.path.exists(filename):
            return None
        
        with open(filename, 'r') as file:
            return json.load(file)
    except Exception as e:
        logger.error(f"Error loading JSON file: {e}")
        return None

def get_severity_color(severity):
    """
    Get color code for a severity level
    
    Args:
        severity (str): Severity level (low, medium, high)
        
    Returns:
        str: Hex color code
    """
    severity_colors = {
        'low': '#00f0ff',    # Cyan
        'medium': '#ffcc00', # Yellow
        'high': '#ff304f'    # Red
    }
    return severity_colors.get(severity.lower(), '#8490a8')

def format_bytes(size):
    """
    Format a byte size into a human-readable string
    
    Args:
        size (int): Size in bytes
        
    Returns:
        str: Formatted size string
    """
    power = 2**10  # 1024
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    
    while size > power and n < 4:
        size /= power
        n += 1
        
    return f"{size:.2f} {power_labels[n]}"
