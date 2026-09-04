import sys
import os
from scapy.all import rdpcap, IP, TCP
from collections import defaultdict
from datetime import datetime


# ==========================================
# 1. CHECK COMMAND-LINE ARGUMENT
# ==========================================

if len(sys.argv) != 2:
    print("Usage: python src/main.py <pcap_file>")
    sys.exit(1)

pcap_file = sys.argv[1]


# ==========================================
# 2. CHECK IF PCAP FILE EXISTS
# ==========================================

if not os.path.exists(pcap_file):
    print(f"Error: File not found - {pcap_file}")
    sys.exit(1)


# ==========================================
# 3. CREATE UNIQUE REPORT FILE
# ==========================================

report_name = os.path.splitext(
    os.path.basename(pcap_file)
)[0]

report_file = f"reports/report_{report_name}.txt"


# ==========================================
# 4. READ PCAP FILE
# ==========================================

print("======================================")
print("     NETWORK SECURITY MONITOR")
print("======================================")
print()

print(f"Analyzing PCAP: {pcap_file}")
print()

packets = rdpcap(pcap_file)


# ==========================================
# 5. DATA STRUCTURES
# ==========================================

# Stores unique destination ports for each
# source -> destination pair
port_connections = defaultdict(set)

# Stores number of connection attempts
connection_attempts = defaultdict(int)

# Stores number of SYN packets between
# each source -> destination pair
syn_burst = defaultdict(int)


# ==========================================
# 6. ANALYZE TCP SYN PACKETS
# ==========================================

for packet in packets:

    if IP in packet and TCP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        destination_port = packet[TCP].dport

        # Only analyze TCP SYN packets
        if packet[TCP].flags == "S":

            # ----------------------------------
            # Port scan detection data
            # ----------------------------------

            port_connections[
                (source_ip, destination_ip)
            ].add(destination_port)

            # ----------------------------------
            # Repeated connection detection data
            # ----------------------------------

            connection_attempts[
                (source_ip, destination_ip, destination_port)
            ] += 1

            # ----------------------------------
            # SYN burst detection data
            # ----------------------------------

            syn_burst[
                (source_ip, destination_ip)
            ] += 1


# ==========================================
# 7. CURRENT TIME
# ==========================================

current_time = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)


# ==========================================
# 8. REPORT HEADER
# ==========================================

report = []

report.append("========================================")
report.append("     NETWORK SECURITY MONITOR REPORT")
report.append("========================================")
report.append("")

report.append(f"Scan Time       : {current_time}")
report.append(f"PCAP File       : {pcap_file}")
report.append(f"Packets Analyzed: {len(packets)}")
report.append("")

report.append("THREATS DETECTED")
report.append("----------------")
report.append("")


# ==========================================
# 9. THREAT COUNTERS
# ==========================================

found_threat = False

total_threats = 0
high_threats = 0
medium_threats = 0


# ==========================================
# 10. PORT SCAN DETECTION
# ==========================================

for (source_ip, destination_ip), ports in port_connections.items():

    # 5 or more different ports
    # may indicate a port scan
    if len(ports) >= 5:

        found_threat = True
        total_threats += 1

        # 10 or more ports = HIGH
        if len(ports) >= 10:

            severity = "HIGH"
            high_threats += 1

        # 5-9 ports = MEDIUM
        else:

            severity = "MEDIUM"
            medium_threats += 1

        alert = [
            f"[{severity}] Possible Port Scan",
            f"Source IP        : {source_ip}",
            f"Destination IP   : {destination_ip}",
            f"Ports Contacted  : {len(ports)}",
            f"Ports            : {sorted(ports)}",
            ""
        ]

        report.extend(alert)


# ==========================================
# 11. REPEATED CONNECTION ATTEMPTS
# ==========================================

for (
    source_ip,
    destination_ip,
    destination_port
), count in connection_attempts.items():

    # 3 or more attempts to the same port
    if count >= 3:

        found_threat = True
        total_threats += 1
        medium_threats += 1

        alert = [
            "[MEDIUM] Repeated Connection Attempts",
            f"Source IP        : {source_ip}",
            f"Destination IP   : {destination_ip}",
            f"Destination Port : {destination_port}",
            f"Attempts         : {count}",
            ""
        ]

        report.extend(alert)


# ==========================================
# 12. SYN BURST DETECTION
# ==========================================

for (source_ip, destination_ip), count in syn_burst.items():

    # 10 or more SYN packets to the same
    # destination may indicate a connection burst
    if count >= 10:

        found_threat = True
        total_threats += 1
        high_threats += 1

        alert = [
            "[HIGH] Possible SYN Flood / Connection Burst",
            f"Source IP        : {source_ip}",
            f"Destination IP   : {destination_ip}",
            f"SYN Packets      : {count}",
            ""
        ]

        report.extend(alert)


# ==========================================
# 13. THREAT SUMMARY
# ==========================================

report.append("SUMMARY")
report.append("-------")

report.append(f"Total Threats  : {total_threats}")
report.append(f"High Severity  : {high_threats}")
report.append(f"Medium Severity: {medium_threats}")

report.append("")


# ==========================================
# 14. NO THREATS FOUND
# ==========================================

if not found_threat:

    report.append("No suspicious activity detected.")
    report.append("")


# ==========================================
# 15. REPORT FOOTER
# ==========================================

report.append("========================================")
report.append("             END OF REPORT")
report.append("========================================")


# ==========================================
# 16. MAKE REPORT DIRECTORY
# ==========================================

os.makedirs("reports", exist_ok=True)


# ==========================================
# 17. SAVE REPORT
# ==========================================

with open(report_file, "w") as file:

    file.write("\n".join(report))


# ==========================================
# 18. DISPLAY RESULT
# ==========================================

print(f"Packets analyzed : {len(packets)}")
print()

print("Threat Summary")
print("--------------")
print(f"Total threats    : {total_threats}")
print(f"High severity    : {high_threats}")
print(f"Medium severity  : {medium_threats}")
print()

print("✅ Analysis completed.")
print(f"📄 Report saved to: {report_file}")
