"""
A simple network sniffer using Scapy.

Usage:
    - No Filter (Capture all traffic):
      python netsniff.py

    - With Filter (e.g., TCP traffic only):
      python netsniff.py --filter "tcp"

    - Specific Interface or Packet Count:
      python netsniff.py --filter "tcp" --iface "eth0" --count 100 
"""
import asyncio
import logging
import argparse
from scapy.all import sniff, IP, TCP

logging.basicConfig(level=logging.INFO, format='%(message)s')

def packet_callback(packet):
    """
    Callback function to process packets. 
    Logs the source and destination of IP and TCP packets.
    
    Args:
        packet: The packet received by the sniffer.
    """
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if TCP in packet:
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                logging.info(f"TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
            else:
                logging.info(f"IP Packet: {ip_src} -> {ip_dst}")
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def start_sniffing(filter_str, iface=None, count=0):
    """
    Starts packet sniffing with the given filter, interface, and packet count.
    
    Args:
        filter_str: BPF filter string.
        iface: Network interface to sniff on.
        count: Number of packets to capture; 0 for infinity.
    """
    logging.info(f"Starting sniffing... Filter: {filter_str}")
    sniff(filter=filter_str, prn=packet_callback, iface=iface, count=count)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Sniffer")
    parser.add_argument("--filter", type=str, default="", help="BPF filter string")
    parser.add_argument("--iface", type=str, help="Interface to sniff on")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 means infinity)")

    args = parser.parse_args()

    asyncio.run(start_sniffing(args.filter, args.iface, args.count))
