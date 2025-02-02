import sys
import time
from scapy.all import sniff, IP, TCP, UDP, ARP

# Function to handle each packet
def handle_packet(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    if packet.haslayer(IP):  # Check for IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto  # Get the protocol (e.g., TCP, UDP, ICMP)
        log_entry = f"{timestamp} - IP Packet: {src_ip} -> {dst_ip} (Protocol: {protocol})"
    elif packet.haslayer(ARP):  # Check for ARP layer
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        log_entry = f"{timestamp} - ARP Packet: {src_ip} -> {dst_ip}"
    else:
        return  # Ignore other packets

    print(log_entry)  # Print to console
    with open("sniffer_log.txt", "a") as log_file:
        log_file.write(log_entry + "\n")  # Write to log file

# Main function to start packet sniffing
def main(interface):
    print(f"Starting packet sniffer on interface {interface}...")
    print("Press Ctrl+C to stop.")
    try:
        sniff(iface=interface, prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Entry point of the script
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sniffer.py <interface>")
        sys.exit(1)
    interface = sys.argv[1]
    main(interface)
