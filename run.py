"""
One-Click Launcher for the NTRO Cyber Threat Detection Dashboard (SIH 2026).
"""
import sys
import os
import subprocess

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    app_path = os.path.join(base_dir, "app", "dashboard", "app.py")

    # Detect virtualenv python if available
    venv_python_win = os.path.join(base_dir, ".venv", "Scripts", "python.exe")
    venv_python_unix = os.path.join(base_dir, ".venv", "bin", "python")

    if os.path.exists(venv_python_win):
        python_exe = venv_python_win
    elif os.path.exists(venv_python_unix):
        python_exe = venv_python_unix
    else:
        python_exe = sys.executable

    print("=" * 70)
    print("NTRO Cyber Threat Detection Dashboard - SIH 2026 (SIH26145)")
    print("Organization: National Technical Research Organisation (NTRO)")
    print("Mode: Passive Unidirectional Sensor Enclave (Read-Only)")
    print("=" * 70)
    print(f"Launching Streamlit application using: {python_exe}")
    print(f"Target: {app_path}")
    print("URL: http://localhost:8501")
    print("=" * 70)

    cmd = [
        python_exe,
        "-m",
        "streamlit",
        "run",
        app_path,
        "--server.headless=false",
        "--server.port=8501",
        "--browser.gatherUsageStats=false"
    ]

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\nShutdown requested by user. Terminating sensor enclave.")

if __name__ == "__main__":
    main()
