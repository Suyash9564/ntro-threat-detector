"""
System Architecture and Physical Topology View for NTRO Threat Detection.
Explains the 8-stage detection pipeline, physical data diode guarantees, and passive intelligence model.
"""
import streamlit as st


def render_architecture():
    st.markdown("""
    <div class="soc-header">
        <div class="soc-title-group">
            <h1>SYSTEM ARCHITECTURE & ENCLAVE TOPOLOGY</h1>
            <p>PASSIVE UNIDIRECTIONAL SENSING &bull; ZERO ACTIVE RETURN PATH &bull; METADATA INGESTION</p>
        </div>
        <div class="soc-badge" style="border-color: #059669; color: #34d399;">PHYSICAL DIODE ENFORCED</div>
    </div>
    """, unsafe_allow_html=True)

    # Visual Topology ASCII / Card Box
    st.markdown("""
    <div style="background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 22px;">
        <div style="font-size: 0.9rem; font-weight: 700; color: #38bdf8; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px;">
            PHYSICAL TOPOLOGY: AIR-GAPPED PASSIVE MONITORING ENCLAVE
        </div>
        <pre style="color: #cbd5e1; font-family: monospace; font-size: 0.85rem; line-height: 1.5; background: transparent; border: none; margin: 0;">
+-----------------------------------------------------------------------------------------+
|                                 MONITORED MISSION NETWORK                               |
|        [Workstations]         [Core Routers]         [Internal Services]                |
+-----------------------------------------------------------------------------------------+
                                             |
                                             | (Passive Optical Splitter / Tap)
                                             v
                      +---------------------------------------------+
                      |         PHYSICAL DATA DIODE (TX ONLY)       |
                      |   Single-strand optical fiber transmit diode|
                      |   NO PHYSICAL REVERSE STRAND (RX DISCONNECTED)
                      +---------------------------------------------+
                                             |
                                             | STRICTLY ONE-WAY IP TRAFFIC
                                             v
                      +---------------------------------------------+
                      |       NTRO PASSIVE MONITORING ENCLAVE       |
                      +---------------------------------------------+
                                             |
    +----------------------------------------+----------------------------------------+
    |                                        |                                        |
    v                                        v                                        v
[1. Traffic Ingestion]             [2. Flow Extraction]                    [3. Feature Engine]
Header extraction (PCAP/Stream)     Bidirectional flow reassembly           Rolling sliding windows
Zero payload decryption             TCP state tracking                      12-D behavioral vector
    |                                        |                                        |
    +----------------------------------------+----------------------------------------+
                                             |
                        +--------------------+--------------------+
                        |                                         |
                        v                                         v
            [4. Statistical Rules]                     [5. ML Anomaly Detection]
            * Volumetric thresholding                  * Scikit-Learn Isolation Forest
            * Fan-out & dispersion analysis            * Unsupervised outlier scoring
            * Periodicity & jitter autocorrelation     * Calibrated anomaly confidence
            * Shannon domain entropy                   * Baseline Gaussian z-scores
                        |                                         |
                        +--------------------+--------------------+
                                             |
                                             v
                               [6. Multi-Modal Threat Scoring]
                               Correlates heuristics + ML confidence
                                             |
                                             v
                                  [7. Alert Synthesis]
                               Standard schema & "Why Flagged" evidence
                                             |
                                             v
                             [8. SOC Console & Analytics UI]
                             Real-time situational awareness
        </pre>
    </div>
    """, unsafe_allow_html=True)

    # 8 Pipeline Stages
    st.markdown("### The 8-Stage Detection Pipeline")

    stages = [
        ("1. Unidirectional Traffic Ingestion", "Traffic enters the security enclave through an optical tap or hardware data diode where the transmit photodiode on the monitored network is physically connected, but the receive photodiode is detached. This provides an unbreachable hardware guarantee that the enclave cannot emit packets or compromise the monitored network."),
        ("2. Passive Flow Extraction", "Raw IP packets are assembled into flow records defined by the standard 5-tuple: (Source IP, Destination IP, Source Port, Destination Port, Protocol). Flow duration, packet rates, byte volumes, and TCP control flags are maintained in an ephemeral, rolling in-memory table."),
        ("3. Rolling Window Feature Engineering", "Telemetry is sliced into 5-to-10 second sliding windows. A 12-dimensional feature vector is extracted, capturing packet rates, SYN ratios, host and port fan-out dispersion, inter-arrival time (IAT) variance, domain Shannon entropy, and outbound-to-inbound byte ratios."),
        ("4. Statistical & Behavioral Detection", "Deterministic heuristics evaluate domain-specific threat signatures: port scan fan-out thresholds (>30 unique ports), C2 periodicity metrics (>85%), DNS entropy calculations (>3.6 bits/char), and asymmetric outbound transfer ratios (>10:1)."),
        ("5. Unsupervised Machine Learning (Isolation Forest)", "A scikit-learn Isolation Forest model trained exclusively on normal baseline traffic scores each window feature vector. Because Isolation Forest isolates anomalies using random partitioning trees, zero-day attacks and novel volumetric shifts are caught without requiring pre-labeled attack samples."),
        ("6. Multi-Modal Threat Scoring & Correlation", "Heuristic indicators and ML anomaly scores are combined into an explainable threat score. The model requires corroborating evidence before elevating severity to CRITICAL, preventing alert fatigue in live SOC environments."),
        ("7. Explainable Alert Synthesis", "For every detection event, the engine synthesizes an actionable ThreatAlert adhering to a standardized schema. Critically, it generates plain-English 'Why did the AI flag this?' bullet points and a side-by-side comparison of the learned baseline versus current observed metrics."),
        ("8. Real-Time SOC Console & Analytics", "The operator console renders live metric cards, streaming traffic volume graphs, a six-threat status matrix, and a drill-down evidence inspector, providing full operational visibility in high-stakes security operations centers.")
    ]

    col_a, col_b = st.columns(2)
    for idx, (title, desc) in enumerate(stages):
        target_col = col_a if idx % 2 == 0 else col_b
        with target_col:
            st.markdown(f"""
            <div style="background: #111827; border: 1px solid #1f2937; border-radius: 6px; padding: 14px 16px; margin-bottom: 12px; height: 100%;">
                <div style="font-size: 0.88rem; font-weight: 700; color: #38bdf8; margin-bottom: 6px;">{title}</div>
                <div style="font-size: 0.78rem; color: #94a3b8; line-height: 1.45;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("### Why Unidirectional Monitoring Matters for NTRO")
    st.markdown("""
    1. **Zero Attack Surface:** Inline inspection appliances can be targeted, blinded, or exploited by adversaries. A passive data diode sensor has no IP address on the monitored network, making it invisible and impossible to attack.
    2. **Air-Gapped Enclave Integrity:** Highly classified military and intelligence enclaves can inspect unclassified border network traffic without opening bidirectional communication bridges that could lead to lateral movement or data leakage.
    3. **Operational Safety:** The sensor cannot accidentally drop, reset, or delay critical operational packets because it has zero inline gating control.
    4. **Legal & Compliance Standards:** Payload decryption often raises sovereign regulatory and privacy concerns. Our metadata-only paradigm provides robust security intelligence without infringing on payload confidentiality.
    """)
