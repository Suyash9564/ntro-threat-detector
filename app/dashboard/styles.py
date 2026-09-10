"""
Cyber SOC Styling and CSS Customizations for NTRO Passive Threat Intelligence.
Dark, authoritative, technical operations styling without neon tropes.
"""

def get_soc_css() -> str:
    return """
    <style>
        /* Base page theme overrides */
        .stApp {
            background-color: #0b0f17;
            color: #e2e8f0;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
        }

        /* Top header bar */
        .soc-header {
            background: linear-gradient(90deg, #0f172a 0%, #1e293b 100%);
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 16px 22px;
            margin-bottom: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .soc-title-group h1 {
            color: #f8fafc;
            font-size: 1.45rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .soc-title-group p {
            color: #94a3b8;
            font-size: 0.82rem;
            margin: 4px 0 0 0;
            letter-spacing: 0.3px;
        }
        .soc-badge {
            background: #1e293b;
            color: #38bdf8;
            border: 1px solid #0284c7;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        .soc-badge-live {
            background: rgba(16, 185, 129, 0.15);
            color: #10b981;
            border: 1px solid #059669;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.8px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .soc-badge-live::before {
            content: "";
            width: 8px;
            height: 8px;
            background-color: #10b981;
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px #10b981;
        }

        /* Metric cards */
        .soc-card {
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 6px;
            padding: 14px 18px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
            transition: border-color 0.2s;
        }
        .soc-card:hover {
            border-color: #374151;
        }
        .soc-card-label {
            color: #9ca3af;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 6px;
        }
        .soc-card-value {
            color: #f9fafb;
            font-size: 1.6rem;
            font-weight: 700;
            line-height: 1.1;
        }
        .soc-card-sub {
            color: #6b7280;
            font-size: 0.72rem;
            margin-top: 4px;
        }

        /* Severity Badges */
        .badge-critical {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid #b91c1c;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
        }
        .badge-high {
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
            border: 1px solid #d97706;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
        }
        .badge-medium {
            background: rgba(234, 179, 8, 0.2);
            color: #eab308;
            border: 1px solid #ca8a04;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
        }
        .badge-normal {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid #059669;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
        }

        /* Diode Notice Banner */
        .diode-banner {
            background: #0f172a;
            border-left: 4px solid #0284c7;
            padding: 10px 14px;
            border-radius: 0 6px 6px 0;
            font-size: 0.78rem;
            color: #94a3b8;
            margin-bottom: 16px;
        }

        /* Threat Overview Grid Cards */
        .threat-matrix-card {
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 6px;
            padding: 12px 14px;
            height: 100%;
        }
        .threat-matrix-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
            padding-bottom: 6px;
            border-bottom: 1px solid #1f2937;
        }
        .threat-matrix-title {
            color: #f3f4f6;
            font-size: 0.85rem;
            font-weight: 600;
        }

        /* Drill down box */
        .why-flagged-box {
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 16px;
            margin-top: 10px;
        }

        /* Table custom styling */
        .dataframe {
            background-color: #111827 !important;
            color: #e5e7eb !important;
            font-size: 0.8rem !important;
        }
    </style>
    """
