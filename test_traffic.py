import scapy.all as scapy
import time
import random
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import argparse

def generate_normal_traffic():
    """Generate normal HTTP traffic"""
    # Normal HTTP request
    ip = IP(dst="8.8.8.8")  # Using Google DNS as an example destination
    tcp = TCP(sport=random.randint(1024, 65535), dport=80, flags='S')
    packet = ip/tcp
    scapy.send(packet, verbose=False)
    time.sleep(0.5)

def generate_neptune_attack():
    """Generate Neptune (SYN flood) attack traffic"""
    # SYN flood characteristics from KDDTrain+ dataset
    ip = IP(dst="8.8.8.8")
    for _ in range(50):  # Send multiple SYN packets rapidly
        tcp = TCP(sport=random.randint(1024, 65535), dport=80, flags='S')
        packet = ip/tcp
        scapy.send(packet, verbose=False)
        time.sleep(0.01)  # Small delay between packets

def generate_land_attack():
    """Generate Land attack traffic (same source and destination)"""
    # Create multiple LAND attack packets
    for _ in range(5):  # Send multiple packets to ensure detection
        ip = IP(src="127.0.0.1", dst="127.0.0.1")  # Same source and destination
        tcp = TCP(sport=1234, dport=80, flags='S')
        packet = ip/tcp
        scapy.send(packet, verbose=False)
        time.sleep(0.1)

def generate_smurf_attack():
    """Generate Smurf attack traffic (ICMP with broadcast)"""
    # Send to multiple broadcast addresses
    broadcast_addresses = [
        "255.255.255.255",  # Global broadcast
        "192.168.255.255",  # Local broadcast
        "224.0.0.1"        # Multicast
    ]
    
    for dst in broadcast_addresses:
        ip = IP(dst=dst)
        icmp = ICMP(type=8, code=0)  # Echo request
        # Create a large packet
        data = b"X" * 1024  # Add 1KB of data
        packet = ip/icmp/data
        scapy.send(packet, verbose=False)
        time.sleep(0.1)

def generate_portscan():
    """Generate port scan traffic"""
    ip = IP(dst="8.8.8.8")
    common_ports = [20, 21, 22, 23, 25, 80, 443, 445, 3389, 8080]  # Common ports to scan
    
    for port in common_ports:
        tcp = TCP(sport=random.randint(1024, 65535), dport=port, flags='S')
        packet = ip/tcp
        scapy.send(packet, verbose=False)
        time.sleep(0.1)

def generate_backdoor_attack():
    """Generate backdoor attack traffic"""
    ip = IP(dst="8.8.8.8")
    backdoor_ports = [20034, 31337, 1234, 4444]  # Common backdoor ports
    
    for port in backdoor_ports:
        tcp = TCP(sport=random.randint(1024, 65535), dport=port, flags='S')
        packet = ip/tcp
        scapy.send(packet, verbose=False)
        time.sleep(0.1)

def generate_buffer_overflow():
    """Generate buffer overflow attack traffic"""
    ip = IP(dst="8.8.8.8")
    tcp = TCP(sport=random.randint(1024, 65535), dport=80, flags='S')
    # Create a large payload
    data = b"A" * 5000  # Large payload to trigger buffer overflow detection
    packet = ip/tcp/data
    scapy.send(packet, verbose=False)
    time.sleep(0.1)

def generate_ftp_write():
    """Generate FTP write attack traffic"""
    ip = IP(dst="8.8.8.8")
    tcp = TCP(sport=random.randint(1024, 65535), dport=21, flags='S')  # FTP control port
    data = b"USER anonymous\r\nPASS test@test.com\r\nPUT malicious.txt\r\n"
    packet = ip/tcp/data
    scapy.send(packet, verbose=False)
    time.sleep(0.1)

def generate_guess_passwd():
    """Generate password guessing attack traffic"""
    ip = IP(dst="8.8.8.8")
    services = {
        'ftp': 21,
        'ssh': 22,
        'telnet': 23,
        'pop3': 110,
        'imap': 143
    }
    
    for service, port in services.items():
        # Send multiple login attempts
        for _ in range(6):  # More than 5 attempts to trigger detection
            tcp = TCP(sport=random.randint(1024, 65535), dport=port, flags='S')
            packet = ip/tcp
            scapy.send(packet, verbose=False)
            time.sleep(0.1)

def generate_ipsweep():
    """Generate IPSweep attack traffic"""
    base_ip = "192.168.1."
    for i in range(1, 5):  # Send ICMP to multiple IPs
        ip = IP(dst=f"{base_ip}{i}")
        icmp = ICMP(type=8, code=0)  # Echo request
        packet = ip/icmp
        scapy.send(packet, verbose=False)
        time.sleep(0.1)

def generate_warezmaster():
    """Generate Warezmaster attack traffic"""
    ip = IP(dst="8.8.8.8")
    tcp = TCP(sport=random.randint(1024, 65535), dport=21, flags='S')  # FTP control port
    # Create large FTP data transfer
    data = b"X" * 3000  # Large data transfer
    packet = ip/tcp/data
    scapy.send(packet, verbose=False)
    time.sleep(0.1)

def generate_backdoor_traffic():
    """Generate traffic to test Snort backdoor rules"""
    ip = IP(dst="8.8.8.8")
    
    # Test various backdoor ports and patterns
    backdoor_tests = [
        # Dagger backdoor
        {'port': 2589, 'payload': b"2\x00\x00\x00\x06\x00\x00\x00Drives\x24\x00"},
        # QAZ Worm
        {'port': 7597, 'payload': b"qazwsx.hsq"},
        # NetBus Pro
        {'port': 20034, 'payload': b"BN\x10\x00\x02\x00\x05\x00"},
        # Infector
        {'port': 146, 'payload': b"FC "},
        # Satan's Backdoor
        {'port': 666, 'payload': b"Remote: You are connected to me.\r\nRemote: Ready for commands"},
        # Doly 2.0
        {'port': 6789, 'payload': b"Wtzup Use"},
    ]
    
    for test in backdoor_tests:
        tcp = TCP(sport=random.randint(1024, 65535), dport=test['port'], flags='S')
        packet = ip/tcp/test['payload']
        scapy.send(packet, verbose=False)
        time.sleep(0.1)

def generate_trojan_traffic():
    """Generate traffic to test Snort trojan rules"""
    ip = IP(dst="8.8.8.8")
    
    # Test various trojan patterns
    trojan_tests = [
        # NetBus
        {'port': 12345, 'payload': b"GetInfo\r"},
        # ADMw0rm
        {'port': 21, 'payload': b"USER w0rm\r\n"},
        # GateCrasher
        {'port': 6969, 'payload': b"GateCrasher v2.0, Server On-Line..."},
    ]
    
    for test in trojan_tests:
        tcp = TCP(sport=random.randint(1024, 65535), dport=test['port'], flags='S')
        packet = ip/tcp/test['payload']
        scapy.send(packet, verbose=False)
        time.sleep(0.1)

def generate_malware_traffic():
    """Generate traffic to test Snort malware rules"""
    ip = IP(dst="8.8.8.8")
    
    # Test various malware patterns
    malware_tests = [
        # Matrix 2.0
        {'proto': 'udp', 'sport': 3344, 'dport': 3345, 'payload': b"activate"},
        # DeepThroat
        {'proto': 'udp', 'sport': random.randint(1024, 65535), 'dport': 2140, 
         'payload': b"Ahhhh My Mouth Is Open"},
        # WinCrash
        {'proto': 'tcp', 'sport': 5714, 'dport': random.randint(1024, 65535), 
         'payload': b"\xB4\xB4"},
    ]
    
    for test in malware_tests:
        if test['proto'] == 'tcp':
            l4_proto = TCP(sport=test['sport'], dport=test['dport'], flags='S')
        else:
            l4_proto = UDP(sport=test['sport'], dport=test['dport'])
        
        packet = ip/l4_proto/test['payload']
        scapy.send(packet, verbose=False)
        time.sleep(0.1)

def main():
    parser = argparse.ArgumentParser(description='Generate test traffic for IDS')
    parser.add_argument('--type', choices=['normal', 'neptune', 'land', 'smurf', 'portscan', 
                                         'backdoor', 'buffer_overflow', 'ftp_write', 'guess_passwd',
                                         'ipsweep', 'warezmaster', 'snort_backdoor', 'snort_trojan',
                                         'snort_malware', 'all'],
                      default='all', help='Type of traffic to generate')
    args = parser.parse_args()

    print("Starting traffic generation...")
    print("Make sure your IDS is running before continuing!")
    time.sleep(2)

    # Dictionary mapping attack types to their generator functions
    attack_generators = {
        'normal': generate_normal_traffic,
        'neptune': generate_neptune_attack,
        'land': generate_land_attack,
        'smurf': generate_smurf_attack,
        'portscan': generate_portscan,
        'backdoor': generate_backdoor_attack,
        'buffer_overflow': generate_buffer_overflow,
        'ftp_write': generate_ftp_write,
        'guess_passwd': generate_guess_passwd,
        'ipsweep': generate_ipsweep,
        'warezmaster': generate_warezmaster,
        'snort_backdoor': generate_backdoor_traffic,
        'snort_trojan': generate_trojan_traffic,
        'snort_malware': generate_malware_traffic
    }

    if args.type == 'all':
        # Run all attack types
        for attack_name, generator in attack_generators.items():
            print(f"\nGenerating {attack_name} traffic...")
            generator()
            time.sleep(1)  # Add delay between attacks
    else:
        # Run specific attack type
        if args.type in attack_generators:
            print(f"\nGenerating {args.type} traffic...")
            attack_generators[args.type]()

    print("\nTraffic generation complete!")

if __name__ == "__main__":
    main() 