import streamlit as st
import requests
import time
import os
import pandas as pd

# --- CONFIGURATION ---
BACKEND_URL = "http://backend:8000/api/v1" 

def show_dual_speedometers(score, vuln_count):
    """Renders two high-tech gauges: Threat Level % and Vulnerability Count (1-10)."""
    # Color logic for Threat Level (%)
    t_color = "#ff4b4b" if score > 70 else "#ffa500" if score > 40 else "#00cc66"
    # Color logic for Vulnerability Count (Range 1-10)
    v_color = "#ff4b4b" if vuln_count > 7 else "#ffa500" if vuln_count > 3 else "#00cc66"
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"""
            <div style="border: 1px solid #3d425c; border-radius: 15px; padding: 20px; text-align: center; background-color: #1e2130; color: white;">
                <p style="margin: 0; font-weight: bold; color: #aaa; text-transform: uppercase; font-size: 0.8rem;">Threat Level</p>
                <h1 style="color: {t_color}; margin: 10px 0; font-size: 2.8rem;">{score}%</h1>
                <div style="width: 100%; background-color: #333; border-radius: 10px; height: 12px;">
                    <div style="width: {score}%; background-color: {t_color}; height: 12px; border-radius: 10px; transition: width 0.5s ease-in-out;"></div>
                </div>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        # Map 1-10 count to 100% for the progress bar width
        v_width = min(vuln_count * 10, 100)
        st.markdown(f"""
            <div style="border: 1px solid #3d425c; border-radius: 15px; padding: 20px; text-align: center; background-color: #1e2130; color: white;">
                <p style="margin: 0; font-weight: bold; color: #aaa; text-transform: uppercase; font-size: 0.8rem;">Vulnerability Count</p>
                <h1 style="color: {v_color}; margin: 10px 0; font-size: 2.8rem;">{vuln_count}</h1>
                <div style="width: 100%; background-color: #333; border-radius: 10px; height: 12px;">
                    <div style="width: {v_width}%; background-color: {v_color}; height: 12px; border-radius: 10px; transition: width 0.5s ease-in-out;"></div>
                </div>
            </div>
        """, unsafe_allow_html=True)

def show_severity_table(vulnerabilities):
    """Displays the distribution table matching the requested CVSS ranges."""
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    ranges = {
        "Critical": "9.0 – 10.0", 
        "High": "7.0 – 8.9", 
        "Medium": "4.0 – 6.9", 
        "Low": "0.1 – 3.9", 
        "Info": "0.0"
    }
    
    for v in vulnerabilities:
        sev = v.get('severity', 'Info').capitalize()
        if sev in stats:
            stats[sev] += 1
            
    df_data = []
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        df_data.append({"Severity": sev, "Count": stats[sev], "CVSS Range": ranges[sev]})
    
    st.table(pd.DataFrame(df_data))

def show():
    role = st.session_state.get('role', 'user')
    user_id = st.session_state.get('user_id', 1) 
    perms = st.session_state.get('perms', ["file_scan"])

    with st.expander("📞 Technical Support & Core Team"):
        c1, c2, c3, c4 = st.columns(4)
        c1.info("**Subh**\n\n7797416720"); c2.info("**Praneel**\n\n93549 73114")
        c3.info("**Animesh**\n\n62029 72581"); c4.info("**Akshan**\n\n94677 45887")

    st.title("🛡️ A.I.G.I.S Security Hub")
    
    tabs = ["Overview"]
    if "file_scan" in perms: tabs.append("📁 File Scan")
    tabs.append("📜 My History")
    if role == "root": tabs.append("👑 Global History (Admin)")
    
    active_tab = st.sidebar.radio("Navigation", tabs)

    if active_tab == "Overview":
        st.subheader("Welcome to Autonomous Guard & Inspection System")
        st.write(f"Logged in as: **{role.upper()}**")
        st.markdown("---")
        st.write("A.I.G.I.S uses **Llama3** and **Static Analysis** to secure your cloud-native apps.")

    elif "File Scan" in active_tab:
        st.header("📁 Static File Analysis")
        uploaded_file = st.file_uploader("Upload script for analysis", type=['py', 'java', 'js', 'exe', 'pdf'])
        
        if uploaded_file and st.button("Start Sandbox Scan", use_container_width=True):
            status_ui = st.empty()
            try:
                files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
                response = requests.post(f"{BACKEND_URL}/scan/file?user_id={user_id}", files=files)
                
                if response.status_code == 200:
                    job_id = response.json().get("job_id")
                    status = "PENDING"
                    
                    while status not in ["completed", "SUCCESS", "failed", "FAILURE"]:
                        status_ui.warning(f"⏳ A.I.G.I.S analyzing... (Job: {str(job_id)[:8]})")
                        time.sleep(5)
                        poll_data = requests.get(f"{BACKEND_URL}/scan/status/{job_id}").json()
                        status = poll_data.get("status") or poll_data.get("state")
                        
                        if status in ["completed", "SUCCESS"]:
                            status_ui.empty()
                            st.success("✅ Analysis Complete!")
                            
                            # Fetch vulnerability data from the result
                            vuln_list = poll_data.get("vulnerabilities_list", [])
                            vuln_count = len(vuln_list)
                            risk_score = poll_data.get("risk_score", 0)

                            # 1. VISUAL ANALYTICS: Dual Gauges
                            show_dual_speedometers(risk_score, vuln_count)

                            # 2. SEVERITY DISTRIBUTION TABLE
                            st.markdown("### 📊 Severity Distribution")
                            show_severity_table(vuln_list)

                            # 3. SHORT ISSUE DESCRIPTIONS
                            st.markdown("### 📋 Detected Issues Summary")
                            if vuln_list:
                                for i, v in enumerate(vuln_list):
                                    with st.expander(f"Issue #{i+1}: {v.get('issue', 'Security Vulnerability')}"):
                                        st.write(f"**Tool:** {v.get('tool', 'Scanner')}")
                                        st.write(f"**Severity:** {v.get('severity', 'N/A')}")
                                        st.write(f"**Description:** {v.get('message', 'No details provided.')}")
                            else:
                                st.info("No major security issues detected.")

                            # 4. DOWNLOAD REPORT
                            st.markdown("---")
                            dl_res = requests.get(f"{BACKEND_URL}/scan/download/{job_id}")
                            st.download_button("📥 Download Full Detailed PDF Report", dl_res.content, f"AIGIS_Report_{job_id[:8]}.pdf", "application/pdf", use_container_width=True)
                            break
            except Exception as e:
                st.error(f"Connection Failed: {e}")

    elif "My History" in active_tab:
        st.header("📜 Your Personal Scan History")
        res = requests.get(f"{BACKEND_URL}/scan/history/me?user_id={user_id}")
        if res.status_code == 200:
            history = res.json()
            if history:
                df = pd.DataFrame(history)
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df = df.sort_values(by='timestamp', ascending=False)
                st.dataframe(df[['filename', 'risk_score', 'timestamp']], use_container_width=True, hide_index=True)
                
                st.markdown("### 📥 Archive Retrieval")
                selected_job = st.selectbox("Select Scan ID:", df['job_id'])
                if st.button("Fetch Archived PDF"):
                    archive_dl = requests.get(f"{BACKEND_URL}/scan/download/{selected_job}")
                    st.download_button("💾 Download Archive", archive_dl.content, f"AIGIS_Archive_{selected_job[:8]}.pdf")
            else:
                st.info("No scan history found for your account.")

    elif "Global History" in active_tab:
        st.header("👑 Root Access: Global Scan Logs")
        res = requests.get(f"{BACKEND_URL}/scan/history/all")
        if res.status_code == 200:
            all_scans = res.json()
            if all_scans:
                df_global = pd.DataFrame(all_scans)
                st.table(df_global)
            else:
                st.info("System has no scan records.")