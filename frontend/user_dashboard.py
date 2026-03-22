import streamlit as st
import requests
import time
import os
import pandas as pd

# --- CONFIGURATION ---
BACKEND_URL = "http://backend:8000/api/v1" 

def show_speedometer(score, label="THREAT LEVEL"):
    """Renders the AIGIS Gauge."""
    color = "#ff4b4b" if score > 70 else "#ffa500" if score > 40 else "#00cc66"
    st.markdown(f"""
        <div style="border: 1px solid #3d425c; border-radius: 15px; padding: 20px; text-align: center; background-color: #1e2130; color: white;">
            <h1 style="color: {color}; margin: 0; font-size: 3rem;">{score}%</h1>
            <p style="margin: 5px 0; font-weight: bold; color: #aaa;">{label}</p>
            <div style="width: 100%; background-color: #333; border-radius: 10px; height: 12px; margin-top: 10px;">
                <div style="width: {score}%; background-color: {color}; height: 12px; border-radius: 10px; transition: width 0.5s ease-in-out;"></div>
            </div>
        </div>
    """, unsafe_allow_html=True)

def show():
    # 1. LOAD SESSION DATA (Ensure your login page sets these!)
    role = st.session_state.get('role', 'user')
    user_id = st.session_state.get('user_id', 1) 
    perms = st.session_state.get('perms', ["file_scan"])

    # --- TECHNICAL SUPPORT ---
    with st.expander("📞 Technical Support & Core Team"):
        c1, c2, c3, c4 = st.columns(4)
        c1.info("**Subh**\n\n7797416720"); c2.info("**Praneel**\n\n93549 73114")
        c3.info("**Animesh**\n\n62029 72581"); c4.info("**Akshan**\n\n94677 45887")

    st.title("🛡️ A.I.G.I.S Security Hub")
    
    # 2. NAVIGATION
    tabs = ["Overview"]
    if "file_scan" in perms: tabs.append("📁 File Scan")
    tabs.append("📜 My History")
    if role == "root": tabs.append("👑 Global History (Admin)")
    
    active_tab = st.sidebar.radio("Navigation", tabs)

    # --- OVERVIEW ---
    if active_tab == "Overview":
        st.subheader("Welcome to Autonomous Guard & Inspection System")
        st.write(f"Logged in as: **{role.upper()}**")
        st.markdown("---")
        st.write("A.I.G.I.S uses **Llama3** and **Static Analysis** to secure your cloud-native apps.")

    # --- FILE SCAN (The Main Logic) ---
    elif "File Scan" in active_tab:
        st.header("📁 Static File Analysis")
        uploaded_file = st.file_uploader("Upload script for analysis", type=['py', 'java', 'js', 'exe', 'pdf'])
        
        if uploaded_file and st.button("Start Sandbox Scan", use_container_width=True):
            status_ui = st.empty()
            try:
                # A. Send File + user_id
                files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
                response = requests.post(f"{BACKEND_URL}/scan/file?user_id={user_id}", files=files)
                
                if response.status_code == 200:
                    job_id = response.json().get("job_id")
                    
                    # B. Polling Loop
                    status = "PENDING"
                    while status not in ["completed", "SUCCESS", "failed", "FAILURE"]:
                        status_ui.warning(f"⏳ A.I.G.I.S analyzing... (Job: {str(job_id)[:8]})")
                        time.sleep(5)
                        poll = requests.get(f"{BACKEND_URL}/scan/status/{job_id}").json()
                        status = poll.get("status") or poll.get("state")
                        
                        if status in ["completed", "SUCCESS"]:
                            status_ui.empty()
                            st.success("✅ Analysis Complete!")
                            show_speedometer(poll.get("risk_score", 0))
                            
                            # C. Download PDF
                            dl_res = requests.get(f"{BACKEND_URL}/scan/download/{job_id}")
                            st.download_button("📥 Download Report", dl_res.content, f"AIGIS_{job_id[:8]}.pdf")
                            break
            except Exception as e:
                st.error(f"Connection Failed: {e}")

    # --- MY HISTORY ---
    elif "My History" in active_tab:
        st.header("📜 Your Personal Scan History")
        res = requests.get(f"{BACKEND_URL}/scan/history/me?user_id={user_id}")
        if res.status_code == 200:
            history = res.json()
            if history:
                df = pd.DataFrame(history)
                # Sort by newest first
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df = df.sort_values(by='timestamp', ascending=False)
                
                st.dataframe(df[['filename', 'risk_score', 'timestamp']], use_container_width=True, hide_index=True)
                
                # Re-download archived reports
                st.markdown("### 📥 Archive Retrieval")
                selected_job = st.selectbox("Select Scan ID:", df['job_id'])
                if st.button("Fetch Archived PDF"):
                    archive_dl = requests.get(f"{BACKEND_URL}/scan/download/{selected_job}")
                    st.download_button("💾 Download Archive", archive_dl.content, f"AIGIS_Archive_{selected_job[:8]}.pdf")
            else:
                st.info("No scan history found for your account.")

    # --- GLOBAL HISTORY (Root Only) ---
    elif "Global History" in active_tab:
        st.header("👑 Root Access: Global Scan Logs")
        res = requests.get(f"{BACKEND_URL}/scan/history/all")
        if res.status_code == 200:
            all_scans = res.json()
            if all_scans:
                df_global = pd.DataFrame(all_scans)
                st.table(df_global) # Shows user, filename, score, time
            else:
                st.info("System has no scan records.")