import streamlit as st
import os
import tempfile
import pandas as pd

from scapy.all import rdpcap, sniff, wrpcap, IP, TCP, UDP
from collections import defaultdict, Counter
from datetime import datetime


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="Network Security Monitor",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# HEADER
# ==========================================

st.title("🛡️ Network Security Monitor")

st.markdown(
    "### Network Security Monitoring & Threat Detection"
)

st.write(
    "Analyze PCAP files or capture network traffic "
    "directly from your system."
)

st.divider()


# ==========================================
# SIDEBAR SETTINGS
# ==========================================

st.sidebar.title("⚙️ Detection Settings")

st.sidebar.write(
    "Adjust the sensitivity of the detection rules."
)

port_scan_threshold = st.sidebar.slider(
    "Port Scan Threshold",
    min_value=3,
    max_value=20,
    value=5
)

high_port_scan_threshold = st.sidebar.slider(
    "High Severity Port Count",
    min_value=5,
    max_value=30,
    value=10
)

repeated_threshold = st.sidebar.slider(
    "Repeated Connection Threshold",
    min_value=2,
    max_value=20,
    value=3
)

syn_burst_threshold = st.sidebar.slider(
    "SYN Burst Threshold",
    min_value=5,
    max_value=100,
    value=10
)

st.sidebar.divider()

st.sidebar.info(
    "Lower thresholds increase sensitivity. "
    "Higher thresholds reduce potential false positives."
)


# ==========================================
# ANALYSIS FUNCTION
# ==========================================

def analyze_packets(
    packets,
    port_scan_threshold,
    high_port_scan_threshold,
    repeated_threshold,
    syn_burst_threshold
):

    port_connections = defaultdict(set)
    connection_attempts = defaultdict(int)
    syn_burst = defaultdict(int)

    source_ips = set()
    destination_ips = set()

    tcp_count = 0
    udp_count = 0

    destination_ports = Counter()

    # ======================================
    # PACKET ANALYSIS
    # ======================================

    for packet in packets:

        # ----------------------------------
        # IP statistics
        # ----------------------------------

        if IP in packet:

            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            source_ips.add(source_ip)
            destination_ips.add(destination_ip)

        # ----------------------------------
        # TCP analysis
        # ----------------------------------

        if IP in packet and TCP in packet:

            tcp_count += 1

            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            destination_port = packet[TCP].dport

            destination_ports[destination_port] += 1

            # Only analyze SYN packets
            if packet[TCP].flags == "S":

                port_connections[
                    (source_ip, destination_ip)
                ].add(destination_port)

                connection_attempts[
                    (
                        source_ip,
                        destination_ip,
                        destination_port
                    )
                ] += 1

                syn_burst[
                    (source_ip, destination_ip)
                ] += 1

        # ----------------------------------
        # UDP analysis
        # ----------------------------------

        elif IP in packet and UDP in packet:

            udp_count += 1

            destination_port = packet[UDP].dport

            destination_ports[destination_port] += 1

    # ======================================
    # THREAT STORAGE
    # ======================================

    threats = []

    high_threats = 0
    medium_threats = 0

    # ======================================
    # PORT SCAN DETECTION
    # ======================================

    for (
        source_ip,
        destination_ip
    ), ports in port_connections.items():

        if len(ports) >= port_scan_threshold:

            if len(ports) >= high_port_scan_threshold:

                severity = "HIGH"
                high_threats += 1

            else:

                severity = "MEDIUM"
                medium_threats += 1

            threats.append({
                "Threat": "Possible Port Scan",
                "Severity": severity,
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "Details": (
                    f"{len(ports)} ports contacted: "
                    f"{sorted(ports)}"
                )
            })

    # ======================================
    # REPEATED CONNECTION DETECTION
    # ======================================

    for (
        source_ip,
        destination_ip,
        destination_port
    ), count in connection_attempts.items():

        if count >= repeated_threshold:

            medium_threats += 1

            threats.append({
                "Threat": "Repeated Connection Attempts",
                "Severity": "MEDIUM",
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "Details": (
                    f"Port {destination_port} "
                    f"attempted {count} times"
                )
            })

    # ======================================
    # SYN BURST DETECTION
    # ======================================

    for (
        source_ip,
        destination_ip
    ), count in syn_burst.items():

        if count >= syn_burst_threshold:

            high_threats += 1

            threats.append({
                "Threat": "Possible SYN Flood / Connection Burst",
                "Severity": "HIGH",
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "Details": (
                    f"{count} SYN packets detected"
                )
            })

    # ======================================
    # RETURN RESULTS
    # ======================================

    return {
        "packets": len(packets),
        "threats": threats,
        "high": high_threats,
        "medium": medium_threats,
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "tcp": tcp_count,
        "udp": udp_count,
        "top_ports": destination_ports.most_common(10)
    }


# ==========================================
# SECURITY RISK CALCULATION
# ==========================================

def calculate_risk(result):

    if result["high"] > 0:

        return {
            "level": "HIGH",
            "icon": "🔴",
            "message": (
                "High-risk network activity was detected."
            ),
            "action": (
                "Investigate the source IP, review affected "
                "ports, and check the associated systems."
            )
        }

    elif result["medium"] > 0:

        return {
            "level": "MEDIUM",
            "icon": "🟠",
            "message": (
                "Suspicious network activity was detected."
            ),
            "action": (
                "Review the detected connections and "
                "determine whether the activity is authorized."
            )
        }

    else:

        return {
            "level": "LOW",
            "icon": "🟢",
            "message": (
                "No suspicious activity was detected."
            ),
            "action": (
                "Continue monitoring network activity "
                "for unusual behavior."
            )
        }


# ==========================================
# REPORT GENERATOR
# ==========================================

def create_report(filename, result, risk):

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    report = []

    report.append("========================================")
    report.append("     NETWORK SECURITY MONITOR REPORT")
    report.append("========================================")
    report.append("")

    report.append(
        f"Scan Time       : {current_time}"
    )

    report.append(
        f"Capture File    : {filename}"
    )

    report.append(
        f"Packets Analyzed: {result['packets']}"
    )

    report.append("")

    # ======================================
    # SECURITY SUMMARY
    # ======================================

    report.append("EXECUTIVE SECURITY SUMMARY")
    report.append("--------------------------")

    report.append(
        f"Risk Level      : {risk['level']}"
    )

    report.append(
        f"Assessment      : {risk['message']}"
    )

    report.append(
        f"Recommended     : {risk['action']}"
    )

    report.append("")

    # ======================================
    # NETWORK STATISTICS
    # ======================================

    report.append("NETWORK STATISTICS")
    report.append("------------------")

    report.append(
        f"Unique Source IPs      : "
        f"{len(result['source_ips'])}"
    )

    report.append(
        f"Unique Destination IPs : "
        f"{len(result['destination_ips'])}"
    )

    report.append(
        f"TCP Packets            : "
        f"{result['tcp']}"
    )

    report.append(
        f"UDP Packets            : "
        f"{result['udp']}"
    )

    report.append("")

    # ======================================
    # THREATS
    # ======================================

    report.append("THREATS DETECTED")
    report.append("----------------")
    report.append("")

    if not result["threats"]:

        report.append(
            "No suspicious activity detected."
        )

    else:

        for threat in result["threats"]:

            report.append(
                f"[{threat['Severity']}] "
                f"{threat['Threat']}"
            )

            report.append(
                f"Source IP        : "
                f"{threat['Source IP']}"
            )

            report.append(
                f"Destination IP   : "
                f"{threat['Destination IP']}"
            )

            report.append(
                f"Details          : "
                f"{threat['Details']}"
            )

            report.append("")

    # ======================================
    # SUMMARY
    # ======================================

    report.append("SUMMARY")
    report.append("-------")

    report.append(
        f"Total Threats  : "
        f"{len(result['threats'])}"
    )

    report.append(
        f"High Severity  : "
        f"{result['high']}"
    )

    report.append(
        f"Medium Severity: "
        f"{result['medium']}"
    )

    report.append("")

    report.append("========================================")
    report.append("             END OF REPORT")
    report.append("========================================")

    return "\n".join(report)


# ==========================================
# DISPLAY RESULTS
# ==========================================

def display_results(result, filename):

    risk = calculate_risk(result)

    # ======================================
    # EXECUTIVE SECURITY SUMMARY
    # ======================================

    st.divider()

    st.subheader("🛡️ Executive Security Summary")

    if risk["level"] == "HIGH":

        st.error(
            f"{risk['icon']} SECURITY RISK: "
            f"{risk['level']}"
        )

    elif risk["level"] == "MEDIUM":

        st.warning(
            f"{risk['icon']} SECURITY RISK: "
            f"{risk['level']}"
        )

    else:

        st.success(
            f"{risk['icon']} SECURITY RISK: "
            f"{risk['level']}"
        )

    st.write(
        f"**Assessment:** {risk['message']}"
    )

    st.info(
        f"💡 **Recommended Action:** "
        f"{risk['action']}"
    )

    # ======================================
    # SECURITY ANALYSIS
    # ======================================

    st.divider()

    st.subheader("📊 Security Analysis")

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "📦 Packets",
            result["packets"]
        )

    with col2:

        st.metric(
            "🚨 Total Threats",
            len(result["threats"])
        )

    with col3:

        st.metric(
            "🔴 High Severity",
            result["high"]
        )

    with col4:

        st.metric(
            "🟠 Medium Severity",
            result["medium"]
        )

    # ======================================
    # NETWORK STATISTICS
    # ======================================

    st.divider()

    st.subheader("🌐 Network Statistics")

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Source IPs",
            len(result["source_ips"])
        )

    with col2:

        st.metric(
            "Destination IPs",
            len(result["destination_ips"])
        )

    with col3:

        st.metric(
            "TCP Packets",
            result["tcp"]
        )

    with col4:

        st.metric(
            "UDP Packets",
            result["udp"]
        )

    # ======================================
    # PROTOCOL BREAKDOWN
    # ======================================

    st.divider()

    st.subheader("📡 Protocol Breakdown")

    protocol_data = pd.DataFrame({
        "Protocol": [
            "TCP",
            "UDP"
        ],
        "Packets": [
            result["tcp"],
            result["udp"]
        ]
    })

    protocol_data = protocol_data.set_index(
        "Protocol"
    )

    st.bar_chart(protocol_data)

    # ======================================
    # TOP PORTS
    # ======================================

    st.divider()

    st.subheader(
        "🔌 Most Contacted Destination Ports"
    )

    if result["top_ports"]:

        port_data = pd.DataFrame(
            result["top_ports"],
            columns=[
                "Port",
                "Packets"
            ]
        )

        port_data["Port"] = port_data[
            "Port"
        ].astype(str)

        port_data = port_data.set_index(
            "Port"
        )

        st.bar_chart(port_data)

    else:

        st.info(
            "No TCP or UDP destination ports found."
        )

    # ======================================
    # THREAT TABLE
    # ======================================

    st.divider()

    st.subheader("🚨 Detected Threats")

    if result["threats"]:

        threat_data = pd.DataFrame(
            result["threats"]
        )

        st.dataframe(
            threat_data,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "✅ No threats were detected."
        )

    # ======================================
    # SEVERITY BREAKDOWN
    # ======================================

    if result["threats"]:

        st.divider()

        st.subheader(
            "📈 Threat Severity Breakdown"
        )

        severity_data = pd.DataFrame({
            "Severity": [
                "High",
                "Medium"
            ],
            "Threats": [
                result["high"],
                result["medium"]
            ]
        })

        severity_data = severity_data.set_index(
            "Severity"
        )

        st.bar_chart(severity_data)

    # ======================================
    # DETAILED FINDINGS
    # ======================================

    if result["threats"]:

        st.divider()

        st.subheader("🔎 Detailed Findings")

        for index, threat in enumerate(
            result["threats"],
            start=1
        ):

            with st.expander(
                f"{index}. "
                f"{threat['Severity']} — "
                f"{threat['Threat']}"
            ):

                st.write(
                    f"**Source IP:** "
                    f"{threat['Source IP']}"
                )

                st.write(
                    f"**Destination IP:** "
                    f"{threat['Destination IP']}"
                )

                st.write(
                    f"**Details:** "
                    f"{threat['Details']}"
                )

    # ======================================
    # REPORT
    # ======================================

    st.divider()

    st.subheader("📄 Security Report")

    report_text = create_report(
        filename,
        result,
        risk
    )

    st.download_button(
        label="⬇️ Download Security Report",
        data=report_text,
        file_name=(
            f"security_report_"
            f"{os.path.splitext(filename)[0]}.txt"
        ),
        mime="text/plain",
        use_container_width=True
    )


# ==========================================
# MODE SELECTION
# ==========================================

mode = st.radio(
    "Choose Analysis Mode",
    [
        "📁 PCAP File Analysis",
        "📡 Live Network Capture"
    ],
    horizontal=True
)


# ==========================================
# PCAP FILE ANALYSIS
# ==========================================

if mode == "📁 PCAP File Analysis":

    st.subheader("📁 Upload PCAP")

    uploaded_file = st.file_uploader(
        "Upload Network Capture",
        type=["pcap", "pcapng"],
        help="Upload a .pcap or .pcapng file."
    )

    if uploaded_file is not None:

        st.success(
            f"Selected file: **{uploaded_file.name}**"
        )

        if st.button(
            "🔍 Analyze PCAP",
            type="primary",
            use_container_width=True
        ):

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".pcap"
            ) as temp_file:

                temp_file.write(
                    uploaded_file.getbuffer()
                )

                temp_path = temp_file.name

            with st.spinner(
                "Analyzing network traffic..."
            ):

                try:

                    packets = rdpcap(temp_path)

                    result = analyze_packets(
                        packets,
                        port_scan_threshold,
                        high_port_scan_threshold,
                        repeated_threshold,
                        syn_burst_threshold
                    )

                except Exception as error:

                    st.error(
                        f"❌ Error analyzing PCAP: "
                        f"{error}"
                    )

                    os.remove(temp_path)
                    st.stop()

            os.remove(temp_path)

            display_results(
                result,
                uploaded_file.name
            )


# ==========================================
# LIVE NETWORK CAPTURE
# ==========================================

else:

    st.subheader("📡 Live Network Capture")

    st.info(
        "Capture traffic from your own machine or "
        "an authorized lab environment only."
    )

    interface = st.text_input(
        "Network Interface",
        value="lo",
        help=(
            "Examples: lo, eth0, wlan0. "
            "Use 'ip addr' in Kali to see interfaces."
        )
    )

    duration = st.slider(
        "Capture Duration (seconds)",
        min_value=5,
        max_value=30,
        value=10
    )

    st.write(
        f"Interface: **{interface}**"
    )

    st.write(
        f"Duration: **{duration} seconds**"
    )

    if st.button(
        "📡 Start Live Capture",
        type="primary",
        use_container_width=True
    ):

        capture_placeholder = st.empty()

        capture_placeholder.info(
            f"Capturing traffic on `{interface}` "
            f"for {duration} seconds..."
        )

        try:

            captured_packets = sniff(
                iface=interface,
                timeout=duration
            )

        except Exception as error:

            st.error(
                f"❌ Live capture failed: {error}"
            )

            st.info(
                "Check the interface name with: "
                "`ip addr`"
            )

            st.stop()

        capture_placeholder.success(
            f"✅ Capture completed — "
            f"{len(captured_packets)} packets captured."
        )

        # ----------------------------------
        # Save live capture
        # ----------------------------------

        live_filename = (
            f"live_capture_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        )

        live_path = os.path.join(
            "data",
            live_filename
        )

        os.makedirs(
            "data",
            exist_ok=True
        )

        wrpcap(
            live_path,
            captured_packets
        )

        # ----------------------------------
        # Analyze live traffic
        # ----------------------------------

        with st.spinner(
            "Analyzing captured traffic..."
        ):

            result = analyze_packets(
                captured_packets,
                port_scan_threshold,
                high_port_scan_threshold,
                repeated_threshold,
                syn_burst_threshold
            )

        display_results(
            result,
            live_filename
        )


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "Network Security Monitoring & Threat Detection "
    "Tool • Python • Scapy • Streamlit"
)
