from scapy.all import *
import time
from datetime import datetime
import random

def generate_aggressive_scan(target_ip="192.168.1.1", num_packets=50):
    """Generate aggressive port scan with multiple flags"""
    print(f"Generating aggressive scan to {target_ip}")
    
    # Common vulnerable ports
    ports = [21, 22, 23, 25, 80, 135, 139, 445, 3306, 3389, 4444, 5900]
    
    for _ in range(num_packets):
        try:
            # Randomly select source port and destination port
            sport = random.randint(1024, 65535)
            dport = random.choice(ports)
            
            # Create packet with random aggressive flags
            flags = random.choice(["S", "SF", "FA", "R", "FPU", "FSRPU"])
            
            # Create and send packet
            pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags=flags)
            send(pkt, verbose=False)
            
            # Very small delay to create rapid succession
            time.sleep(0.01)
            
        except Exception as e:
            print(f"Error sending packet: {e}")

def generate_rapid_syn_flood(target_ip="192.168.1.1", num_packets=100):
    """Generate rapid SYN flood attack"""
    print(f"Generating rapid SYN flood to {target_ip}")
    
    for _ in range(num_packets):
        try:
            # Create SYN packet to random ports in quick succession
            sport = random.randint(1024, 65535)
            dport = random.randint(1, 1024)  # Target lower ports
            
            pkt = IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="S")
            send(pkt, verbose=False)
            
            # Minimal delay for rapid succession
            time.sleep(0.01)
            
        except Exception as e:
            print(f"Error sending packet: {e}")

def generate_mixed_attack_traffic(target_ip="192.168.1.1"):
    """Generate mixed attack traffic with various suspicious patterns"""
    print(f"Generating mixed attack traffic to {target_ip}")
    
    try:
        # Phase 1: Quick port scan
        for port in [21, 22, 23, 25, 80, 445]:
            pkt = IP(dst=target_ip)/TCP(sport=RandShort(), dport=port, flags="S")
            send(pkt, verbose=False)
            time.sleep(0.01)
        
        # Phase 2: Suspicious flag combinations
        for port in [135, 139, 445]:
            # FIN-PSH-URG scan
            pkt = IP(dst=target_ip)/TCP(sport=RandShort(), dport=port, flags="FPU")
            send(pkt, verbose=False)
            time.sleep(0.01)
            
            # RST-FIN scan
            pkt = IP(dst=target_ip)/TCP(sport=RandShort(), dport=port, flags="FR")
            send(pkt, verbose=False)
            time.sleep(0.01)
        
        # Phase 3: Rapid SYN to same port
        target_port = 445
        for _ in range(10):
            pkt = IP(dst=target_ip)/TCP(sport=RandShort(), dport=target_port, flags="S")
            send(pkt, verbose=False)
            time.sleep(0.01)
            
    except Exception as e:
        print(f"Error in mixed attack traffic: {e}")

def main():
    # Configure Scapy
    conf.verb = 0
    
    print("Network Attack Traffic Generator")
    print("-------------------------------")
    print("This tool will generate network traffic that should trigger")
    print("high probability alerts (>0.7) in the anomaly detection system.")
    print("\nMake sure the anomaly detection window is running and capturing!")
    
    # Get target IP
    default_target = "192.168.1.1"
    target_ip = input(f"\nEnter target IP [default: {default_target}]: ").strip() or default_target
    
    while True:
        try:
            print("\nSelect attack pattern to generate:")
            print("1. Aggressive Port Scan (High-probability pattern)")
            print("2. Rapid SYN Flood (High-probability pattern)")
            print("3. Mixed Attack Traffic (Multiple high-probability patterns)")
            print("4. Generate All Attack Patterns")
            print("0. Exit")
            
            choice = input("\nEnter your choice (0-4): ")
            
            if choice == "1":
                generate_aggressive_scan(target_ip)
            elif choice == "2":
                generate_rapid_syn_flood(target_ip)
            elif choice == "3":
                generate_mixed_attack_traffic(target_ip)
            elif choice == "4":
                print("\nGenerating all attack patterns...")
                generate_aggressive_scan(target_ip)
                time.sleep(1)
                generate_rapid_syn_flood(target_ip)
                time.sleep(1)
                generate_mixed_attack_traffic(target_ip)
            elif choice == "0":
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")
                
        except KeyboardInterrupt:
            print("\nStopping attack traffic generation...")
            break
        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    main() 