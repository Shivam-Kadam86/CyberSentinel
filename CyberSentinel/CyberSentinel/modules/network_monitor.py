"""
Network Monitor Module for NebulaGuard IDS
Handles packet capture and basic filtering functionality
"""

import logging
from scapy.all import sniff, conf
from scapy.error import Scapy_Exception

# Configure logging
logger = logging.getLogger(__name__)

class NetworkMonitor:
    """Network packet capturing and monitoring functionality"""
    
    def __init__(self, interface=None):
        """
        Initialize the network monitor
        
        Args:
            interface (str, optional): Network interface to monitor. If None, uses default interface.
        """
        self.interface = interface or conf.iface
        logger.debug(f"NetworkMonitor initialized on interface: {self.interface}")
    
    def capture_packets(self, count=10, timeout=None, filter_str=None):
        """
        Capture network packets
        
        Args:
            count (int): Maximum number of packets to capture
            timeout (int, optional): Stop capturing after specified seconds
            filter_str (str, optional): BPF filter string to filter packets
            
        Returns:
            list: Captured network packets
        """
        try:
            logger.debug(f"Capturing {count} packets (timeout: {timeout}s, filter: {filter_str})")
            
            # Capture packets using scapy's sniff function
            packets = sniff(
                iface=self.interface,
                count=count,
                timeout=timeout,
                filter=filter_str,
                store=True,
                prn=None
            )
            
            logger.debug(f"Captured {len(packets)} packets")
            return packets
            
        except Scapy_Exception as e:
            logger.error(f"Scapy error during packet capture: {e}")
            return []
        except PermissionError as e:
            logger.error(f"Permission error during packet capture: {e}. Try running with elevated privileges.")
            return []
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            return []
    
    def set_interface(self, interface):
        """
        Change the network interface
        
        Args:
            interface (str): New network interface to monitor
        """
        self.interface = interface
        logger.debug(f"Changed monitoring interface to: {self.interface}")
        
    def get_available_interfaces(self):
        """
        Get list of available network interfaces
        
        Returns:
            list: Available network interfaces
        """
        try:
            interfaces = conf.ifaces.keys()
            return list(interfaces)
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            return []

    def get_current_interface(self):
        """
        Get current network interface used for monitoring
        
        Returns:
            str: Current network interface name
        """
        return self.interface
