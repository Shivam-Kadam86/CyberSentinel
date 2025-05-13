"""
Email Sender Module for NebulaGuard IDS
Handles sending emails with attachments
"""

import os
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import formatdate

# Configure logging
logger = logging.getLogger(__name__)

def send_email(recipient, subject, message, attachment_path=None, sender=None):
    """
    Send an email with optional attachment
    
    Args:
        recipient (str): Recipient email address
        subject (str): Email subject
        message (str): Email message body
        attachment_path (str, optional): Path to file to attach
        sender (str, optional): Sender email address. If None, uses environment variable
        
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        # Get email configuration from environment variables
        smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.environ.get('SMTP_PORT', 587))
        smtp_username = os.environ.get('SMTP_USERNAME')
        smtp_password = os.environ.get('SMTP_PASSWORD')
        
        # If sender not specified, use SMTP username or a default
        if not sender:
            sender = smtp_username or 'nebulaGuard@example.com'
        
        # Log configuration (excluding password)
        logger.debug(f"Email configuration: Server={smtp_server}, Port={smtp_port}, Username={smtp_username}")
        
        # Validate required parameters
        if not smtp_username or not smtp_password:
            logger.error("SMTP username and password must be set in environment variables")
            raise ValueError("SMTP credentials not configured. Check environment variables.")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipient
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
        
        # Add message body
        msg.attach(MIMEText(message))
        
        # Add attachment if specified
        if attachment_path and os.path.exists(attachment_path):
            logger.debug(f"Attaching file: {attachment_path}")
            with open(attachment_path, "rb") as file:
                part = MIMEApplication(file.read(), Name=os.path.basename(attachment_path))
            
            # Add header with filename
            part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
            msg.attach(part)
        
        # Connect to SMTP server
        logger.debug(f"Connecting to SMTP server: {smtp_server}:{smtp_port}")
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        
        # Use TLS if available
        if smtp_port == 587:
            server.starttls()
            server.ehlo()
        
        # Login and send
        server.login(smtp_username, smtp_password)
        server.sendmail(sender, recipient, msg.as_string())
        server.close()
        
        logger.info(f"Email sent successfully to {recipient}")
        return True
    
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP authentication failed. Check your username and password.")
        raise
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
        raise
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        raise
