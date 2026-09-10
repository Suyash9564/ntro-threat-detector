"""
Threat Analysis Deep-Dive View for NTRO Presentation & Evaluation.
Provides comprehensive architectural and mathematical explanations for all six threat classes.
"""
import streamlit as st
import json
from app.alerts.schema import ThreatClass, Severity


def render_threat_analysis():
    st.markdown("""
    <div class="soc-header">
        <div class="soc-title-group">
            <h1>THREAT ANALYSIS & DETECTION METHODOLOGY</h1>
            <p>DETAILED TAXONOMY, MATHEMATICAL FEATURES, AND PASSIVE HEURISTICS FOR ALL 6 PS CLASSES</p>
        </div>
        <div class="soc-badge">PS ID: SIH26145</div>
    </div>
    """, unsafe_allow_html=True)

    threat_tabs = st.tabs([
        "1. Volumetric / Protocol DDoS",
        "2. Botnet C2 Beaconing",
        "3. DGA Domains & DNS Tunnelling",
        "4. Encrypted Session Anomaly",
        "5. Reconnaissance / Port Scanning",
        "6. Data Exfiltration"
    ])

    # TAB 1: DDoS
    with threat_tabs[0]:
        st.subheader("1. Volumetric & Protocol Distributed Denial of Service (DDoS)")
        c1, c2 = st.columns([1.2, 1.0])
        with c1:
            st.markdown("""
            **What it is:**
            Coordinated overwhelming of network bandwidth or stateful connection tables (SYN queues) by distributed hosts or spoofed IP floods.

            **Observable Unidirectional Telemetry:**
            - Massive rate surge in incoming packets/sec and Mbps over short sliding windows.
            - Heavy skew in TCP flags (SYN ratio > 80% with minimal corresponding ACK completions).
            - Extreme dispersion of source IP addresses (spoofed botnet swarm targeting single victim IP).

            **Features & Metrics:**
            - `packet_rate`: Packets ingested per second (normal: ~1,200 pkt/s, surge: 50,000+ pkt/s).
            - `syn_ratio`: Percentage of total flows bearing the SYN control flag.
            - `src_diversity`: Cardinality of distinct source IPs targeting victim destination.
            - `volume_deviation`: Z-score deviation against Gaussian moving baseline.

            **Passive Detection Logic:**
            Dual-stage evaluation: Threshold rule triggers on rate surge (>4x baseline) AND high SYN ratio (>65%), corroborated by Isolation Forest volumetric feature outliers.
            """)
        with c2:
            st.markdown("#### Sample Alert Payload")
            st.json({
                "threat_class": "DDOS",
                "severity": "CRITICAL",
                "confidence": 0.98,
                "source_ip": "Distributed (342 IPs)",
                "destination": "10.0.0.5:443",
                "evidence": {
                    "estimated_mbps": 52.4,
                    "packets_per_sec": 51200,
                    "syn_packet_ratio": "88.4%",
                    "baseline_multiplier": "10.5x"
                }
            })

    # TAB 2: C2 Beaconing
    with threat_tabs[1]:
        st.subheader("2. Botnet Command & Control (C2) Beaconing")
        c1, c2 = st.columns([1.2, 1.0])
        with c1:
            st.markdown("""
            **What it is:**
            Automated, scheduled heartbeats emitted by malware implants contacting external C2 servers to report status and receive tasking instructions.

            **Observable Unidirectional Telemetry:**
            - Highly recurring communication between a single internal host and a specific external IP.
            - Rigid, uniform inter-arrival times (e.g. exactly 5.0 seconds).
            - Near-zero jitter / timing variance, characteristic of machine loops rather than human browsing.

            **Features & Metrics:**
            - `inter_arrival_time (IAT)`: Delta time between consecutive session initiations.
            - `iat_variance / jitter`: Variance of IAT ($Var(t) < 0.1s$).
            - `periodicity_score`: Normalized spectral / autocorrelation density ($P > 0.85$).
            - `destination_repetition`: Recurrence count of destination endpoint.

            **Passive Detection Logic:**
            Pairwise host tracking calculates rolling IAT standard deviation. When connection count $\ge 4$ and jitter $< 0.2s$ or periodicity $> 0.85$, alert is dispatched with 90–96% confidence.
            """)
        with c2:
            st.markdown("#### Sample Alert Payload")
            st.json({
                "threat_class": "C2_BEACON",
                "severity": "HIGH",
                "confidence": 0.95,
                "source_ip": "10.0.2.88",
                "destination": "185.220.101.5:443",
                "evidence": {
                    "inter_arrival_time": "5.0s",
                    "timing_jitter_variance": "+/- 0.02s",
                    "periodicity_score": "96.2%",
                    "repetition_count": 22
                }
            })

    # TAB 3: DGA / DNS Tunnelling
    with threat_tabs[2]:
        st.subheader("3. DGA Domains & DNS Tunnelling")
        c1, c2 = st.columns([1.2, 1.0])
        with c1:
            st.markdown("""
            **What it is:**
            - **DGA (Domain Generation Algorithms):** Malware generates hundreds of pseudorandom domains daily for resilient C2 rendezvous.
            - **DNS Tunnelling:** Encapsulation of arbitrary data within DNS queries/responses (TXT/NULL records) to bypass firewalls.

            **Observable Unidirectional Telemetry:**
            - Domain strings with extreme Shannon entropy ($H > 3.6$ bits/char).
            - Unusually long subdomains (e.g., >25 characters) with high consonant clusters.
            - Spikes in non-standard query record types (TXT, NULL, ANY).
            - Abnormally high query frequency to single apex domains.

            **Mathematical Formulation:**
            $$H(X) = -\\sum_{i=1}^{n} P(x_i) \\log_2 P(x_i)$$
            Where $P(x_i)$ is character frequency. Benign domains (e.g. `google.com`) yield $H \\approx 2.1 - 2.6$, whereas DGA strings yield $H \\approx 3.8 - 4.4$.
            """)
        with c2:
            st.markdown("#### Sample Alert Payload")
            st.json({
                "threat_class": "DGA_DNS",
                "severity": "HIGH",
                "confidence": 0.96,
                "source_ip": "10.0.5.114",
                "destination": "10.0.0.2:53 (DNS)",
                "evidence": {
                    "queried_domain": "xqj9k28bfmwz91lpa0c.threatcorp.biz",
                    "shannon_entropy": "3.924 bits/symbol",
                    "domain_label_length": "28 chars",
                    "record_type": "TXT",
                    "query_frequency": "14.5 queries/sec"
                }
            })

    # TAB 4: Encrypted Anomaly
    with threat_tabs[3]:
        st.subheader("4. Malware Inside Encrypted Sessions (Metadata Only)")
        c1, c2 = st.columns([1.2, 1.0])
        with c1:
            st.markdown("""
            **What it is:**
            Malware utilizing modern TLS 1.3 / QUIC encryption to conceal command payload.

            **CRITICAL GUARANTEE — ZERO PAYLOAD DECRYPTION:**
            Per sovereign NTRO passive requirements, the enclave **never decrypts payloads**, breaks TLS handshakes, or mounts MITM certificates. Analysis is strictly metadata-driven.

            **Observable Unidirectional Telemetry:**
            - **Packet Length Distribution:** C2 frameworks (e.g. CobaltStrike malleable profiles) exhibit distinct packet size variance and fixed response buffers.
            - **Burst Timing Variance:** Programmatic request/response bursts deviate from interactive browser rendering.
            - **TLS Client Hello Metadata:** Client cipher suite order, extension sequences, and SNI framing length.

            **Features & Metrics:**
            - `packet_size_variance`: Statistical variance of segment lengths ($Var(L) > 650$).
            - `timing_variance`: Inter-packet arrival burstiness.
            - `tls_fingerprint`: Hashed or raw cipher suite list from unencrypted Client Hello.
            """)
        with c2:
            st.markdown("#### Sample Alert Payload")
            st.json({
                "threat_class": "ENCRYPTED_ANOMALY",
                "severity": "HIGH",
                "confidence": 0.93,
                "source_ip": "10.0.7.62",
                "destination": "194.26.29.11:8443 (TLS)",
                "evidence": {
                    "payload_decryption_status": "STRICTLY DISABLED (Metadata-Only)",
                    "packet_size_variance": "890.5 bytes^2",
                    "burst_timing_variance": "3.85s",
                    "tls_client_fingerprint": "771,4865-4866-4867,0-23-65281..."
                }
            })

    # TAB 5: Port Scanning
    with threat_tabs[4]:
        st.subheader("5. Reconnaissance & Port Scanning")
        c1, c2 = st.columns([1.2, 1.0])
        with c1:
            st.markdown("""
            **What it is:**
            Adversary or automated worm mapping live internal hosts, open ports, and vulnerable services.

            **Observable Unidirectional Telemetry:**
            - Single source IP initiating rapid connections to dozens of unique ports (vertical scan) or across multiple subnet IPs (horizontal sweep).
            - High fan-out ratio ($\text{unique ports} / \text{unique hosts} > 3.0$).
            - Abnormal connection rate (30–60 flows/sec).
            - Rapid TCP SYN probes with zero corresponding data payloads.

            **Detection Thresholds:**
            - Unique ports contacted: $\ge 30$ in 5-second sliding window.
            - Target hosts contacted: $\ge 6$.
            - Baseline comparison: Benign client contacts $\le 3$ unique ports/min.
            """)
        with c2:
            st.markdown("#### Sample Alert Payload")
            st.json({
                "threat_class": "PORT_SCAN",
                "severity": "HIGH",
                "confidence": 0.96,
                "source_ip": "10.0.4.21",
                "destination": "10.0.4.0/24",
                "evidence": {
                    "unique_destination_ports": 47,
                    "unique_destination_hosts": 13,
                    "connection_rate": "38.2 flows/sec",
                    "time_window_duration": "3.1 sec"
                }
            })

    # TAB 6: Exfiltration
    with threat_tabs[5]:
        st.subheader("6. Data Exfiltration")
        c1, c2 = st.columns([1.2, 1.0])
        with c1:
            st.markdown("""
            **What it is:**
            Unauthorized egress of sensitive enterprise data (documents, credentials, databases) to an adversary-controlled external repository.

            **Observable Unidirectional Telemetry:**
            - Inversion of standard browsing asymmetry: typical client download ratio is $\approx 0.3:1$ (out/in), whereas exfiltration yields $> 50:1$.
            - Sustained high-volume outbound bytes (multi-megabyte uploads).
            - Egress target is an unclassified or historically rare external IP.

            **Features & Metrics:**
            - `out_in_ratio`: $\text{bytes\_out} / \max(1, \text{bytes\_in})$.
            - `bytes_out`: Aggregate outbound payload volume.
            - `destination_rarity`: Statistical frequency index of external destination IP.
            """)
        with c2:
            st.markdown("#### Sample Alert Payload")
            st.json({
                "threat_class": "EXFILTRATION",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "source_ip": "10.0.3.45",
                "destination": "198.51.100.77:443",
                "evidence": {
                    "outbound_bytes": "1.42 MB",
                    "inbound_bytes": "2.4 KB",
                    "outbound_inbound_ratio": "520.8:1",
                    "destination_classification": "Uncategorized External IP (Rarity: 99.4%)"
                }
            })
