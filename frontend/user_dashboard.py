import streamlit as st
import requests
import time
import os

# --- CONSTANTS ---
BACKEND_URL = "http://backend:8000/api/v1" 

def show_speedometer(score, label="THREAT LEVEL"):
    """Displays a visual gauge for threat assessment."""
    color = "#ff4b4b" if score > 70 else "#ffa500" if score > 40 else "#00cc66"
    st.markdown(f"""
        <div style="border: 1px solid #3d425c; border-radius: 15px; padding: 20px; text-align: center; background-color: #1e2130; color: white;">
            <h1 style="color: {color}; margin: 0; font-size: 3rem;">{score}%</h1>
            <p style="margin: 5px 0; font-weight: bold; color: #aaa;">{label}</p>
            <div style="width: 100%; background-color: #333; border-radius: 10px; height: 12px; margin-top: 10px;">
                <div style="width: {score}%; background-color: {color}; height: 12px; border-radius: 10px;"></div>
            </div>
        </div>
    """, unsafe_allow_html=True)

def show():
    # --- SUPPORT HEADER ---
    with st.expander("📞 Technical Support & Core Team"):
        c1, c2, c3, c4 = st.columns(4)
        c1.info("**Subh**\n\n7797416720"); c2.info("**Praneel**\n\n93549 73114")
        c3.info("**Animesh**\n\n62029 72581"); c4.info("**Akshan**\n\n94677 45887")

    st.title("🛡️ A.I.G.I.S Analysis Engine")
    
    perms = st.session_state.get('perms', [])
    tabs = ["Overview"]
    if "file_scan" in perms: tabs.append("📁 File Scan")
    if "link_scan" in perms: tabs.append("🔗 Link Scan")
    
    active_tab = st.sidebar.radio("Navigation", tabs)

    if active_tab == "Overview":
        st.subheader("Autonomous Guard & Inspection System")
        st.markdown("Welcome to the future of **Cloud-Native Security**.")

    elif "File Scan" in active_tab:
        st.header("📁 Static File Analysis")
        uploaded_file = st.file_uploader("Upload file for AIGIS Sandbox", type=['py', 'java', 'js', 'exe', 'pdf'])
        
        if uploaded_file:
            if st.button("Start Sandbox Scan", use_container_width=True):
                with st.spinner("Analyzing threat vectors..."):
                    files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
                    try:
                        # 1. Dispatch the scan
                        response = requests.post(f"{BACKEND_URL}/scan/file", files=files)
                        if response.status_code == 200:
                            data = response.json()
                            job_id = data.get("job_id") # Ensure backend returns this
                            
                            # 2. Polling loop to wait for the background worker
                            status = "PENDING"
                            while status in ["PENDING", "STARTED"]:
                                time.sleep(2)
                                poll_res = requests.get(f"{BACKEND_URL}/scan/status/{job_id}")
                                if poll_res.status_code == 200:
                                    result = poll_res.json()
                                    status = result.get("status")
                                    
                                    if status == "completed":
                                        st.success("✅ Analysis Complete!")
                                        show_speedometer(result.get("risk_score", 0))
                                        
                                        # 3. Fetch the file for local download
                                        dl_url = f"{BACKEND_URL}/scan/download/{job_id}"
                                        file_content = requests.get(dl_url).content
                                        
                                        st.download_button(
                                            label="📥 Download Security Report (PDF)",
                                            data=file_content,
                                            file_name=f"AIGIS_Report_{job_id}.pdf",
                                            mime="application/pdf"
                                        )
                                    elif status == "failed":
                                        st.error(f"Scan failed: {result.get('error')}")
                                        break
                        else:
                            st.error(f"Engine Error: {response.status_code}")
                    except Exception as e:
                        st.error(f"Backend Offline: {e}")