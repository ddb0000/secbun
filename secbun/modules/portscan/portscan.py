import asyncio
import socket
import sys
import logging
import json
import argparse
from scapy.all import sr1, IP, TCP

logging.basicConfig(level=logging.INFO, format='%(message)s')

async def get_banner(ip, port):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_banner, ip, port)

def _get_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip('\n').strip('\r')
        s.close()
        return banner
    except:
        return ''

async def scan_port(ip, port, scan_results):
    loop = asyncio.get_event_loop()
    result = {'port': port, 'state': 'CLOSED', 'banner': ''}
    try:
        conn = await loop.run_in_executor(None, _create_connection, ip, port)
        if conn == 0:
            banner = await get_banner(ip, port)
            result['state'] = 'OPEN'
            result['banner'] = banner
            logging.info(f"{port}:OPEN:{banner}")
        else:
            logging.info(f"{port}:CLOSED")
    except Exception as e:
        logging.error(f"{e}:{port}")
    finally:
        scan_results[port] = result

def _create_connection(ip, port):
    syn_packet = IP(dst=ip)/TCP(dport=port, flags='S')
    response = sr1(syn_packet, timeout=1, verbose=0)
    if response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags & 0x12:
        return 0
    else:
        return 1

async def port_scan(target, port_range):
    start_port, end_port = map(int, port_range.split("-"))
    scan_results = {}
    tasks = []
    for port in range(start_port, end_port + 1):
        await asyncio.sleep(scan_rate)
        task = asyncio.create_task(scan_port(target, port, scan_results))
        tasks.append(task)
    await asyncio.gather(*tasks)
    return scan_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Asynchronous Port Scanner")
    parser.add_argument("target", type=str, help="Target IP")
    parser.add_argument("port_range", type=str, help="Port range (e.g., 1-100)")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--rate", type=float, default=0.1, help="Scan rate (delay between scans in seconds)")

    args = parser.parse_args()

    target_ip = args.target
    port_range = args.port_range
    scan_rate = args.rate
    results = asyncio.run(port_scan(target_ip, port_range))
    OPEN_ports = {port: status for port, status in results.items() if status['state'] == 'OPEN'}

    if args.json:
        print(json.dumps(OPEN_ports, indent=2))
    else:
        print(f"\nScan Summary for {target_ip}:")
        for port, status in OPEN_ports.items():
            print(f"{port}:{status['state']}:{status['banner']}")
