import streamlit as st
import requests
import time
import pandas as pd

BACKEND_URL = "http://backend:8000"


def auth_headers():
    return {"Authorization": f"Bearer {st.session_state.token}"}


# ── Visual components ──────────────────────────────────────────────────────────

def show_dual_speedometers(score: int, vuln_count: int):
    t_color = (
        "#ff4b4b" if score > 70
        else "#ffa500" if score > 40
        else "#00cc66"
    )
    v_color = (
        "#ff4b4b" if vuln_count > 7
        else "#ffa500" if vuln_count > 3
        else "#00cc66"
    )
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"""
            <div style="border:1px solid #3d425c;border-radius:15px;
                        padding:20px;text-align:center;
                        background-color:#1e2130;color:white;">
                <p style="margin:0;font-weight:bold;color:#aaa;
                          text-transform:uppercase;font-size:0.8rem;">
                    Threat Level
                </p>
                <h1 style="color:{t_color};margin:10px 0;font-size:2.8rem;">
                    {score}%
                </h1>
                <div style="width:100%;background-color:#333;
                            border-radius:10px;height:12px;">
                    <div style="width:{score}%;background-color:{t_color};
                                height:12px;border-radius:10px;"></div>
                </div>
            </div>
        """, unsafe_allow_html=True)
    with col2:
        v_width = min(vuln_count * 10, 100)
        st.markdown(f"""
            <div style="border:1px solid #3d425c;border-radius:15px;
                        padding:20px;text-align:center;
                        background-color:#1e2130;color:white;">
                <p style="margin:0;font-weight:bold;color:#aaa;
                          text-transform:uppercase;font-size:0.8rem;">
                    Vulnerabilities Found
                </p>
                <h1 style="color:{v_color};margin:10px 0;font-size:2.8rem;">
                    {vuln_count}
                </h1>
                <div style="width:100%;background-color:#333;
                            border-radius:10px;height:12px;">
                    <div style="width:{v_width}%;background-color:{v_color};
                                height:12px;border-radius:10px;"></div>
                </div>
            </div>
        """, unsafe_allow_html=True)


def show_severity_table(vulnerabilities: list):
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    ranges = {
        "Critical": "9.0 – 10.0",
        "High":     "7.0 – 8.9",
        "Medium":   "4.0 – 6.9",
        "Low":      "0.1 – 3.9",
        "Info":     "0.0",
    }
    for v in vulnerabilities:
        sev = v.get("severity", "info").capitalize()
        if sev in stats:
            stats[sev] += 1
    st.table(pd.DataFrame([
        {"Severity": s, "Count": stats[s], "CVSS Range": ranges[s]}
        for s in ["Critical", "High", "Medium", "Low", "Info"]
    ]))


# ── Progress bar polling ───────────────────────────────────────────────────────

SCAN_STAGES = [
    (0.05, "📥 Job received"),
    (0.20, "🔍 Identifying file type"),
    (0.35, "🛠️  Dispatching security tools"),
    (0.55, "⚙️  Running tools in sandbox"),
    (0.75, "🧠 Generating AI remediation"),
    (0.90, "📄 Building PDF report"),
    (1.00, "✅ Complete"),
]


def poll_until_complete(job_id: str):
    progress_bar = st.progress(0.0)
    status_text = st.empty()

    cancel_col, _ = st.columns([1, 4])
    cancel_clicked = cancel_col.button(
        "🛑 Cancel Scan", key=f"cancel_{job_id}"
    )

    if cancel_clicked:
        try:
            resp = requests.delete(
                f"{BACKEND_URL}/api/scan/cancel/{job_id}",
                headers=auth_headers(),
                timeout=10
            )
            if resp.status_code == 200:
                progress_bar.empty()
                status_text.warning("Scan cancelled.")
            else:
                status_text.error(f"Could not cancel: {resp.text}")
        except Exception as e:
            status_text.error(f"Cancel error: {e}")
        return None

    stage_index = 0

    while True:
        try:
            resp = requests.get(
                f"{BACKEND_URL}/api/scan/status/{job_id}",
                headers=auth_headers(),
                timeout=15
            )
            if resp.status_code == 401:
                st.error("Session expired. Please log in again.")
                st.session_state.clear()
                st.rerun()

            data = resp.json()
            backend_status = data.get("status", "")

            if backend_status == "completed":
                progress_bar.progress(1.0)
                status_text.success("✅ Scan complete!")
                time.sleep(0.5)
                progress_bar.empty()
                status_text.empty()
                return data.get("result", {})

            elif backend_status == "failed":
                progress_bar.empty()
                status_text.empty()
                result = data.get("result", {})
                st.error(
                    f"Scan failed: {result.get('error', 'Unknown error')}"
                )
                return None

            elif backend_status in ("pending", "running"):
                if stage_index < len(SCAN_STAGES) - 2:
                    stage_index += 1
                pct, label = SCAN_STAGES[stage_index]
                progress_bar.progress(pct)
                status_text.warning(
                    f"{label}  —  Job: `{job_id[:8]}`"
                )
                time.sleep(5)
            else:
                time.sleep(5)

        except Exception as e:
            progress_bar.empty()
            status_text.empty()
            st.error(f"Polling error: {e}")
            return None


def show_scan_result(result: dict, job_id: str):
    if not result:
        return
    vuln_count = result.get("vulnerabilities", 0)
    threat_score = min(vuln_count * 10, 100)
    st.success("✅ Analysis Complete!")
    st.markdown("---")
    show_dual_speedometers(threat_score, vuln_count)
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    col1.metric("Total Vulnerabilities", vuln_count)
    col2.metric("Threat Score", f"{threat_score}%")
    st.markdown("---")
    st.markdown("### 📄 Full Report")
    st.info(
        "The complete report with all vulnerability details, "
        "CVSS scores, and AI remediation is in the PDF below."
    )
    _show_download_button(job_id)


def _show_download_button(job_id: str):
    try:
        dl_resp = requests.get(
            f"{BACKEND_URL}/api/reports/{job_id}/download",
            headers=auth_headers(),
            timeout=30
        )
        if dl_resp.status_code == 200:
            st.download_button(
                label="📥 Download Full PDF Report",
                data=dl_resp.content,
                file_name=f"AIGIS_Report_{job_id[:8]}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        elif dl_resp.status_code == 404:
            st.warning(
                "Report is still being finalized. "
                "Check My Reports in a moment."
            )
        else:
            st.warning(f"Could not fetch report: {dl_resp.status_code}")
    except Exception as e:
        st.warning(f"Could not fetch report: {e}")


# ── Shared page functions (imported by admin_dashboard too) ────────────────────

def page_file_scan():
    st.header("📁 Static File Analysis")
    st.caption(
        "File type is detected by binary inspection — "
        "renaming a file does not fool the scanner."
    )
    uploaded_file = st.file_uploader(
        "Choose a file to scan",
        type=[
            "py", "js", "ts", "java", "c", "cpp",
            "go", "rb", "php", "exe", "elf", "bin", "so"
        ]
    )
    if uploaded_file:
        st.info(f"Ready to scan: **{uploaded_file.name}**")
        if st.button("🚀 Start Scan", use_container_width=True):
            try:
                files = {
                    "file": (uploaded_file.name, uploaded_file.getvalue())
                }
                resp = requests.post(
                    f"{BACKEND_URL}/api/scan/upload",
                    files=files,
                    headers=auth_headers(),
                    timeout=30
                )
                if resp.status_code == 401:
                    st.error("Session expired.")
                    st.session_state.clear()
                    st.rerun()
                elif resp.status_code == 429:
                    st.error(
                        "Too many scans queued. "
                        "Please wait a moment before scanning again."
                    )
                elif resp.status_code == 200:
                    job_id = resp.json().get("job_id")
                    st.info(f"Scan queued — Job ID: `{job_id}`")
                    result = poll_until_complete(job_id)
                    show_scan_result(result, job_id)
                else:
                    st.error(f"Upload failed: {resp.text}")
            except requests.exceptions.ConnectionError:
                st.error("Cannot connect to backend.")
            except Exception as e:
                st.error(f"Error: {e}")


def page_url_scan():
    st.header("🌐 URL / Web Application Scan")
    st.caption(
        "Runs nikto, nmap, whatweb and wafw00f. "
        "Private/internal IPs are blocked."
    )
    url_input = st.text_input(
        "Target URL", placeholder="https://example.com"
    )
    if url_input:
        if st.button("🚀 Start URL Scan", use_container_width=True):
            try:
                resp = requests.post(
                    f"{BACKEND_URL}/api/scan/url",
                    json={"url": url_input},
                    headers=auth_headers(),
                    timeout=30
                )
                if resp.status_code == 401:
                    st.error("Session expired.")
                    st.session_state.clear()
                    st.rerun()
                elif resp.status_code == 429:
                    st.error("Too many URL scans. Please wait a moment.")
                elif resp.status_code == 422:
                    detail = resp.json().get("detail", [])
                    msg = (
                        detail[0].get("msg", "Invalid URL")
                        if isinstance(detail, list) and detail
                        else "Invalid URL format."
                    )
                    st.error(msg)
                elif resp.status_code == 200:
                    job_id = resp.json().get("job_id")
                    st.info(f"URL scan queued — Job ID: `{job_id}`")
                    result = poll_until_complete(job_id)
                    show_scan_result(result, job_id)
                else:
                    st.error(f"Request failed: {resp.text}")
            except requests.exceptions.ConnectionError:
                st.error("Cannot connect to backend.")
            except Exception as e:
                st.error(f"Error: {e}")


def page_repo_scan():
    st.header("📦 GitHub / GitLab Repository Scan")
    st.caption(
        "Scans public repos with semgrep, gitleaks and trufflehog. "
        "Only public repositories are supported."
    )
    repo_input = st.text_input(
        "Repository URL",
        placeholder="https://github.com/owner/repo"
    )
    branch_input = st.text_input(
        "Branch", value="main", placeholder="main"
    )
    if repo_input:
        if st.button("🚀 Start Repository Scan", use_container_width=True):
            st.warning(
                "Repository scans take several minutes "
                "depending on repo size."
            )
            try:
                resp = requests.post(
                    f"{BACKEND_URL}/api/scan/repository",
                    json={
                        "repo_url": repo_input,
                        "branch": branch_input or "main"
                    },
                    headers=auth_headers(),
                    timeout=30
                )
                if resp.status_code == 401:
                    st.error("Session expired.")
                    st.session_state.clear()
                    st.rerun()
                elif resp.status_code == 429:
                    st.error(
                        "Too many repository scans. Please wait a moment."
                    )
                elif resp.status_code == 422:
                    detail = resp.json().get("detail", [])
                    msg = (
                        detail[0].get("msg", "Invalid URL")
                        if isinstance(detail, list) and detail
                        else "Invalid repository URL."
                    )
                    st.error(msg)
                elif resp.status_code == 200:
                    job_id = resp.json().get("job_id")
                    st.info(f"Repo scan queued — Job ID: `{job_id}`")
                    result = poll_until_complete(job_id)
                    show_scan_result(result, job_id)
                else:
                    st.error(f"Request failed: {resp.text}")
            except requests.exceptions.ConnectionError:
                st.error("Cannot connect to backend.")
            except Exception as e:
                st.error(f"Error: {e}")


def page_my_reports():
    st.header("📜 My Scan Reports")

    try:
        resp = requests.get(
            f"{BACKEND_URL}/api/reports/",
            headers=auth_headers(),
            timeout=10
        )
        if resp.status_code == 401:
            st.error("Session expired.")
            st.session_state.clear()
            st.rerun()
        elif resp.status_code == 200:
            reports = resp.json()
            if not reports:
                st.info(
                    "No reports yet. "
                    "Run a scan to generate your first report."
                )
                return

            st.caption(f"Total reports: **{len(reports)}**")

            # ── Scan history chart ─────────────────────────────────────────
            if len(reports) > 1:
                st.markdown("### 📈 Vulnerability History")
                df_chart = pd.DataFrame([
                    {
                        "Scan": (
                            r.get("target", "")[-30:] + " " +
                            r.get("created_at", "")[:10]
                        ),
                        "Vulnerabilities": r.get("vulnerability_count", 0),
                    }
                    for r in reversed(reports)
                ])
                st.bar_chart(
                    df_chart.set_index("Scan")["Vulnerabilities"]
                )

            # ── History table ──────────────────────────────────────────────
            st.markdown("### 📋 Scan History")

            sev_icons = {
                "critical": "🔴",
                "high":     "🟠",
                "medium":   "🟡",
                "low":      "🟢",
                "info":     "🔵",
                "none":     "⚪",
            }

            df_table = pd.DataFrame([
                {
                    "Date": (
                        r.get("created_at", "")[:19].replace("T", " ")
                    ),
                    "Type": r.get("scan_type", "file").upper(),
                    "Target": r.get("target", "N/A")[-50:],
                    "Vulns": r.get("vulnerability_count", 0),
                    "Threat %": (
                        f"{r.get('threat_score', 0.0):.0f}%"
                    ),
                    "Highest": (
                        sev_icons.get(
                            r.get("highest_severity", "none"), "⚪"
                        ) + " " +
                        r.get("highest_severity", "none").capitalize()
                    ),
                }
                for r in reports
            ])
            st.dataframe(
                df_table,
                use_container_width=True,
                hide_index=True
            )

            # ── Per-report download ────────────────────────────────────────
            st.markdown("### 📥 Download Reports")
            for r in reports:
                job_id = r.get("job_id", "")
                scan_type = r.get("scan_type", "file").upper()
                target = r.get("target", "N/A")
                created = (
                    r.get("created_at", "")[:19].replace("T", " ")
                )
                vuln_count = r.get("vulnerability_count", 0)

                with st.expander(
                    f"[{scan_type}] {target[:50]} — "
                    f"{vuln_count} vulns — {created}"
                ):
                    st.caption(f"Job ID: `{job_id}`")
                    try:
                        dl_resp = requests.get(
                            f"{BACKEND_URL}/api/reports"
                            f"/{job_id}/download",
                            headers=auth_headers(),
                            timeout=30
                        )
                        if dl_resp.status_code == 200:
                            st.download_button(
                                label="📥 Download PDF",
                                data=dl_resp.content,
                                file_name=f"AIGIS_{job_id[:8]}.pdf",
                                mime="application/pdf",
                                key=f"dl_{job_id}"
                            )
                        else:
                            st.warning("Report file not available.")
                    except Exception:
                        st.warning("Could not fetch report file.")
        else:
            st.error(f"Could not load reports: {resp.text}")
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to backend.")
    except Exception as e:
        st.error(f"Error: {e}")


# ── Main show ──────────────────────────────────────────────────────────────────

def show():
    st.title("🛡️ A.I.G.I.S Security Hub")
    st.caption(
        f"Welcome, **{st.session_state.username}** — "
        "Autonomous Intelligence & Guard Inspection System"
    )

    page = st.sidebar.radio(
        "Navigation",
        [
            "🏠 Overview",
            "📁 File Scan",
            "🌐 URL Scan",
            "📦 Repository Scan",
            "📜 My Reports"
        ]
    )

    if page == "🏠 Overview":
        st.subheader("Welcome to A.I.G.I.S")
        st.markdown("""
        A.I.G.I.S uses **Llama 3** and **static analysis** to secure
        your code and infrastructure.

        **What you can scan:**
        - 📁 **Files** — Python, JS, Java, C/C++, Go, Ruby, PHP, Binaries
        - 🌐 **URLs** — nikto, nmap, whatweb, wafw00f
        - 📦 **Repos** — semgrep, gitleaks, trufflehog

        **How it works:**
        1. Submit your target
        2. Tools run in an isolated Docker sandbox
        3. CVSS v3.1 scoring on every finding
        4. Llama 3 generates plain-English fixes
        5. PDF report generated and ready to download
        """)
        col1, col2, col3 = st.columns(3)
        col1.info("🔒 Isolated Docker sandbox")
        col2.info("🤖 Llama 3 (local, private)")
        col3.info("📄 PDF report every scan")

    elif page == "📁 File Scan":
        page_file_scan()
    elif page == "🌐 URL Scan":
        page_url_scan()
    elif page == "📦 Repository Scan":
        page_repo_scan()
    elif page == "📜 My Reports":
        page_my_reports()