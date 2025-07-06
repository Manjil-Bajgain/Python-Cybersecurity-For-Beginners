import os          # For executing system-level commands (like iptables)
import sys         # For exiting the script if needed
import time        # For timing and rate calculations
from collections import defaultdict  # To track how many packets each IP sends
from scapy.all import sniff, IP      # Scapy tools for sniffing packets and handling IP layer

# Packet rate threshold: if an IP sends more than this many packets per second, block it
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# This function is called automatically for every captured packet
def packet_callback(packet):
    src_ip = packet[IP].src  # Extract the source IP address from the packet
    packet_count[src_ip] += 1  # Increment the packet count for this IP

    current_time = time.time()  # Get current time
    time_interval = current_time - start_time[0]  # Calculate time since last check

    # If more than 1 second has passed, evaluate packet rates
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval  # Calculate packets per second

            # If the rate exceeds the threshold and IP isn't already blocked
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                
                # Block the IP using iptables (Linux firewall)
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                
                # Add IP to the blocked list to avoid re-blocking
                blocked_ips.add(ip)

        # Reset counters and time for the next interval
        packet_count.clear()
        start_time[0] = current_time

# Run the code only if this file is executed directly
if __name__ == "__main__":
    # Check for root privileges (required to sniff packets and run iptables)
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    # Dictionary to track packet counts for each IP (auto-initialized to 0)
    packet_count = defaultdict(int)

    # List used to store the start time (mutable to allow updates inside function)
    start_time = [time.time()]

    # Set to track already blocked IPs (to avoid redundant iptables rules)
    blocked_ips = set()

    print("Monitoring network traffic...")

    # Start sniffing IP packets and call packet_callback for each one
    sniff(filter="ip", prn=packet_callback)
