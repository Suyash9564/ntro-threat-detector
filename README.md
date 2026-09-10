# NTRO Passive Cyber Threat Intelligence (CTI) Dashboard
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Smart India Hackathon (SIH) 2026** &bull; **Problem Statement ID:** `SIH26145`  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  

---

## 1. Executive Summary & Problem Context

In sovereign defense and intelligence operations, secure government and military networks are physically isolated or connected to external networks strictly through **hardware data diodes** or **passive optical splitters**.

### The Unidirectional IP Traffic Paradigm
A data diode uses a single strand of optical glass that physically transmits light in only **one direction**:
* **Physical Guarantee:** The transmit photodiode on the monitored network is active; the receive photodiode on the sensor side is physically detached or omitted.
* **Zero Reverse Path:** The sensor enclave **cannot transmit a single bit** back onto the monitored network.
* **Zero Active Probing:** The sensor can never send ICMP pings, SYN packets, port scans, or RST resets.
* **Zero Payload Decryption:** The sensor strictly inspects packet headers and flow metadata. TLS 1.3 and QUIC payloads remain **completely encrypted** and uncompromised.

Standard security appliances (inline firewalls, IPS, active vulnerability scanners) completely fail in this environment because they rely on bidirectional handshakes, active probing, and connection resets. 

**This project implements a high-performance, passive, AI-assisted network threat intelligence system** designed from the ground up for strictly one-way IP telemetry streams.

---

## 2. The 8-Stage Detection Pipeline

```
+------------------------+
|   MONITORED NETWORK    |
+------------------------+
            | (Passive Optical Tap)
            v
+------------------------+
|  PHYSICAL DATA DIODE   |  <--- Hardware-enforced one-way optical fiber
+------------------------+
            | (Strictly One-Way IP Traffic)
            v
[1. Traffic Ingestion]       ---> Passive header extraction (Stream/PCAP)
            |
            v
[2. Flow Extraction]         ---> Ephemeral 5-tuple flow reassembly (IP, Port, Proto)
            |
            v
[3. Feature Engineering]     ---> Rolling 5–10s windows; 12-D behavioral feature vector
            |
    +-------+-------+
    |               |
    v               v
[4. Rules]      [5. ML Anomaly] ---> Scikit-Learn Isolation Forest on normal baseline
    |               |
    +-------+-------+
            |
            v
[6. Threat Scoring]          ---> Correlates statistical rules + ML anomaly confidence
            |
            v
[7. Alert Synthesis]         ---> Generates structured alert with "Why Flagged" evidence
            |
            v
[8. SOC Console]             ---> Real-time operator dashboard with traffic graphs
```

---

## 3. The Six Required Threat Classes

The platform actively detects all six threat categories mandated by NTRO Problem Statement `SIH26145`:

| Threat Category | Primary Observable Heuristics | Key Extracted Features | Detection Logic |
| :--- | :--- | :--- | :--- |
| **1. Volumetric / Protocol DDoS** | SYN flood, UDP flood, spoofed botnet swarm, volume surges | `packet_rate`, `byte_rate`, `syn_ratio`, `src_diversity` | Bandwidth surge (>4x baseline) + SYN ratio (>65%) + ML rate outlier. |
| **2. Botnet C2 Beaconing** | Rigid periodic heartbeats, minimal jitter, small destination set | `inter_arrival_time`, `iat_variance`, `periodicity_score` | Autocorrelation periodicity score $>0.85$ and timing jitter $<0.2s$. |
| **3. DGA Domains & DNS Tunnelling** | High-entropy pseudorandom domains, TXT/NULL record spikes | `entropy`, `domain_length`, `query_frequency`, `record_type` | Shannon entropy $H > 3.6$ bits/char + query length $>22$ chars. |
| **4. Encrypted Session Anomaly** | Malware over TLS/QUIC without payload decryption | `packet_size_variance`, `timing_variance`, `tls_fingerprint` | Packet length distribution skewness and burst timing variance (Metadata only). |
| **5. Reconnaissance / Port Scan** | Horizontal sweeps, vertical port scans, high fan-out | `unique_dst_ports`, `unique_dst_hosts`, `fan_out_ratio` | $\ge 30$ unique ports probed across internal hosts within 5s window. |
| **6. Data Exfiltration** | Outbound/inbound ratio inversion, sustained large uploads | `out_in_ratio`, `bytes_out`, `destination_rarity` | Outbound/inbound ratio $>10:1$ and sustained multi-megabyte transfers. |

---

## 4. Machine Learning & Statistical Engine

### Unsupervised Isolation Forest
Rather than faking ML or relying on static rules alone, the system trains a real `sklearn.ensemble.IsolationForest` model on a calibrated synthetic normal network traffic baseline:
* **Training Matrix:** 400+ normal traffic feature windows capturing typical enterprise web browsing, DNS queries, and background service traffic.
* **Inference:** Each sliding window generates a 12-dimensional vector:
  `[packet_rate, byte_rate, syn_ratio, unique_dst_ports, unique_dst_hosts, fan_out_ratio, iat_variance, periodicity_score, dns_entropy_max, packet_size_variance, out_in_ratio, connection_rate]`
* **Decision Function:** Evaluates the average path length across 120 isolation trees. Negative scores indicate high anomaly density, mapped directly to an explainable **Anomaly Confidence Index [0% – 99%]**.
* **Z-Score Outlier Attribution:** Identifies which specific features deviated by $\ge 2.5\sigma$ from the learned Gaussian baseline.

---

## 5. Explainable AI ("Why Was This Flagged?")

For every alert, the system generates human-readable evidence answering: **"Why did the AI flag this?"**

### Example: Port Scan Alert
* **Threat:** Reconnaissance / Port Scan (`HIGH` Severity, 96% Confidence)
* **Source:** `10.0.4.21` &rarr; **Target:** `10.0.4.0/24`
* **Evidence:**
  * Source host `10.0.4.21` contacted 47 distinct destination ports within 3.1 seconds (threshold: 25).
  * Fan-out sweep expanded across 13 internal subnet hosts without completing application handshakes.
  * Connection rate reached 38.2 flows/sec, exceeding benign baseline by 14.2x.
  * Unsupervised ML Isolation Forest confirmed port dispersion anomaly (confidence: 96%).

### Baseline vs. Current Observation Table
| Metric | Learned Normal Baseline | Current Observed Telemetry |
| :--- | :--- | :--- |
| Unique Dst Ports / Host | 3 | 47 |
| Unique Dst Hosts / Min | 2 | 13 |
| Connection Rate (flows/s) | 2.4 | 38.2 |
| Fan-Out Ratio | 1.2 | 3.6 |

---

## 6. Automated Demo Sequence

The dashboard includes a dedicated **▶ START DEMO** controller that loops through the evaluation lifecycle:

```
[Phase 1: Normal Traffic (~16s)]
           |
           v
[Phase 2: Port Scan Reconnaissance (~12s)]  ---> Generates PORT SCAN alert (96% conf)
           |
           v
[Phase 3: Normal Traffic Baseline (~10s)]  ---> Metrics return to normal
           |
           v
[Phase 4: Botnet C2 Beaconing (~14s)]       ---> Generates C2 BEACON alert (95% conf)
           |
           v
[Phase 5: Volumetric DDoS Surge (~14s)]     ---> Traffic surges to ~50 Mbps; DDOS alert (98% conf)
           |
           v
[Phase 6: Normal Traffic Recovery (~10s)]   ---> Seamless loop back to Phase 1
```

* **Demo Controls:** Pause, Resume, Stop, Reset, Speed Multiplier (0.5x, 1x, 2x).
* **Manual Overrides:** Test any of the 6 threat classes individually on demand.

---

## 7. Installation & Quick Start

The project runs locally on standard Windows development machines with minimal setup:

### Step 1: Clone or Navigate to Project
```powershell
cd C:\Users\Arnav\.gemini\antigravity\scratch\ntro-threat-detector
```

### Step 2: Install Dependencies (If not using included venv)
```powershell
pip install -r requirements.txt
```

### Step 3: Run Unit Tests
```powershell
.venv\Scripts\python.exe -m pytest tests/ -v
```

### Step 4: Launch the Dashboard
```powershell
.venv\Scripts\python.exe run.py
```
Open your browser at **`http://localhost:8501`**.

---

## 8. Real-World Deployment vs. Demo Prototype

To maintain complete academic and operational honesty:

| Dimension | Demonstration Prototype (This App) | Real-World Operational Enclave (NTRO) |
| :--- | :--- | :--- |
| **Ingestion Medium** | Simulated synthetic flow generator & PCAP replay | Physical hardware data diode (10Gbps+ single-mode fiber optical tap) |
| **Pipeline Language** | Python (Streamlit, Pandas, Scikit-learn) | Compiled C++ / Rust with kernel bypass (DPDK / AF_XDP) |
| **Throughput** | ~1,200 – 8,500 flows/sec (Demo Benchmark) | 10,000,000+ packets/sec line-rate |
| **Telemetry Format** | Python dictionaries / NetFlow v9 JSON | IPFIX / sFlow / Raw Ethernet frames |
| **Hardware Footprint** | Standard Windows/Linux workstation | Air-gapped multi-node high-performance compute cluster |

---

## 9. Project Structure

```
ntro-threat-detector/
├── app/
│   ├── alerts/
│   │   ├── schema.py           # Standardized alert dataclass & ThreatClass enum
│   │   └── store.py            # Thread-safe in-memory alert repository
│   ├── simulation/
│   │   ├── generator.py        # Telemetry generator with 6 threat profiles
│   │   ├── scenarios.py        # 6-phase automated demo loop & speed control
│   │   └── sources.py          # TrafficSource ABC (Simulated & PCAP sources)
│   ├── features/
│   │   └── extractor.py        # Window-based 12-D feature vector extractor
│   ├── models/
│   │   └── anomaly_detector.py # Scikit-Learn Isolation Forest with score normalizer
│   ├── detection/
│   │   ├── ddos.py             # Volumetric & protocol DDoS detector
│   │   ├── port_scan.py        # Reconnaissance & port sweep detector
│   │   ├── beaconing.py        # C2 periodic beaconing detector
│   │   ├── dns_threats.py      # DGA domain & DNS tunnel detector
│   │   ├── encrypted_anomaly.py# Metadata-only encrypted session anomaly detector
│   │   ├── exfiltration.py     # Data exfiltration detector
│   │   └── engine.py           # Multi-modal detection orchestrator
│   └── dashboard/
│       ├── app.py              # Streamlit entrypoint & multi-page router
│       ├── styles.py           # Cyber SOC CSS styling
│       └── views/
│           ├── live_console.py # Real-time SOC dashboard, graphs, & alert feed
│           ├── threat_analysis.py # Deep-dive into all 6 threat classes
│           ├── architecture.py # Visual diode topology & 8-stage pipeline
│           └── pcap_replay.py  # PCAP upload & throughput benchmark
├── data/
│   └── samples/
│       └── sample_threats.pcap # Sample packet capture for offline ingestion
├── tests/
│   ├── test_simulation.py      # Telemetry & Shannon entropy tests
│   ├── test_features.py        # Feature vector extraction tests
│   ├── test_ml_model.py        # Isolation Forest baseline & scoring tests
│   ├── test_detectors.py       # All 6 threat detectors unit tests
│   └── test_alerts.py          # Alert schema & store tests
├── requirements.txt
├── README.md
└── run.py                      # One-click launcher
```
