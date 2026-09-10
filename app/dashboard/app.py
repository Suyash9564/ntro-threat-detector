"""
Main Streamlit Application Entrypoint for NTRO Passive Threat Intelligence.
SIH 2026 Problem Statement SIH26145 - National Technical Research Organisation.
"""
import streamlit as st
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.dashboard.styles import get_soc_css
from app.simulation.scenarios import DemoScenarioCoordinator
from app.alerts.store import AlertStore
from app.detection.engine import ThreatDetectionEngine
from app.dashboard.views.live_console import render_live_console
from app.dashboard.views.threat_analysis import render_threat_analysis
from app.dashboard.views.architecture import render_architecture
from app.dashboard.views.pcap_replay import render_pcap_replay

# 1. Page Configuration
st.set_page_config(
    page_title="NTRO Cyber Threat Detection Console | SIH 2026",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Inject Dark SOC CSS Styling
st.markdown(get_soc_css(), unsafe_allow_html=True)

# 3. Global Session State Initialization
if "store" not in st.session_state:
    st.session_state.store = AlertStore()

if "engine" not in st.session_state:
    st.session_state.engine = ThreatDetectionEngine(alert_store=st.session_state.store)

if "coordinator" not in st.session_state:
    st.session_state.coordinator = DemoScenarioCoordinator(speed_multiplier=1.0)

if "traffic_history" not in st.session_state:
    st.session_state.traffic_history = []

if "selected_scenario" not in st.session_state:
    st.session_state.selected_scenario = "FULL_SEQUENCE"

if "selected_alert_id" not in st.session_state:
    st.session_state.selected_alert_id = None

# 4. Sidebar Navigation & Enclave Controls
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 10px 0; border-bottom: 1px solid #1e293b; margin-bottom: 14px;">
        <div style="font-size: 1.6rem;">🛡️</div>
        <div style="font-size: 1.15rem; font-weight: 800; color: #f8fafc; letter-spacing: 1px;">NTRO CTI ENCLAVE</div>
        <div style="font-size: 0.72rem; color: #38bdf8; font-weight: 600;">PASSIVE UNIDIRECTIONAL DETECTOR</div>
        <div style="font-size: 0.68rem; color: #64748b; margin-top: 2px;">SIH 2026 &bull; PS ID: SIH26145</div>
    </div>
    """, unsafe_allow_html=True)

    page = st.radio(
        "Navigation Menu",
        options=[
            "🖥️ Live SOC Console",
            "🔍 Threat Analysis Deep-Dive",
            "🏛️ System Architecture & Diode",
            "⚡ PCAP Replay & Benchmark"
        ],
        index=0,
        key="nav_menu"
    )

    st.markdown("---")
    st.markdown("<div style='font-size: 0.75rem; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin-bottom: 8px;'>HARDWARE ENCLAVE ASSURANCES</div>", unsafe_allow_html=True)

    st.markdown("""
    <div style="font-size: 0.75rem; color: #cbd5e1; line-height: 1.5; background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 10px;">
        <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
            <span style="color: #10b981;">✔</span> <strong>Optical Diode:</strong> TX Only
        </div>
        <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
            <span style="color: #10b981;">✔</span> <strong>Reverse Path:</strong> Physically Absent
        </div>
        <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
            <span style="color: #10b981;">✔</span> <strong>Active Probes:</strong> Strict 0%
        </div>
        <div style="display: flex; align-items: center; gap: 6px;">
            <span style="color: #10b981;">✔</span> <strong>TLS Decryption:</strong> Disabled
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("<div style='font-size: 0.72rem; color: #64748b; text-align: center;'>National Technical Research Organisation<br>Theme: Blockchain & Cybersecurity</div>", unsafe_allow_html=True)

# 5. Route to Selected View
if page == "🖥️ Live SOC Console":
    render_live_console()
elif page == "🔍 Threat Analysis Deep-Dive":
    render_threat_analysis()
elif page == "🏛️ System Architecture & Diode":
    render_architecture()
elif page == "⚡ PCAP Replay & Benchmark":
    render_pcap_replay()
