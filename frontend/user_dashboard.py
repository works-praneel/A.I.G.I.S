import streamlit as st
import requests
import time

# --- CONSTANTS ---
BACKEND_URL = "http://localhost:8000/api/v1"

def show_speedometer(score, label="THREAT LEVEL"):
    color = "#ff4b4b" if score > 70 else "#ffa500" if score > 40 else "#00cc66"
    st.markdown(f"""
        <div style="border: 2px solid #ddd; border-radius: 15px; padding: 20px; text-align: center; background-color: #f9f9f9;">
            <h1 style="color: {color}; margin: 0;">{score}%</h1>
            <p style="margin: 5px 0; font-weight: bold; color: #555;">{label}</p>
            <div style="width: 100%; background-color: #eee; border-radius: 10px; height: 12px;">
                <div style="width: {score}%; background-color: {color}; height: 12px; border-radius: 10px;"></div>
            </div>
        </div>
    """, unsafe_allow_value=True)

def show():
    st.title("🛡️ AIGIS Analysis Engine")
    perms = st.session_state.perms
    
    tabs = ["Overview"]
    if "file_scan" in perms: tabs.append("📁 File Scan")
    if "link_scan" in perms: tabs.append("🔗 Link Scan")
    if "github_scan" in perms: tabs.append("🐙 GitHub Scan")
    
    active_tab = st.sidebar.radio("Navigation", tabs)

    # --- LINK SCAN REAL IMPLEMENTATION ---
    if "Link Scan" in active_tab:
        st.subheader("🔗 URL Threat Analysis")
        url = st.text_input("Enter target URL", placeholder="https://example.com")
        
        if st.button("Initiate URL Scan", use_container_width=True):
            if url:
                with st.spinner(f"Sending {url} to AIGIS Backend..."):
                    try:
                        # Real API Call to your FastAPI backend
                        response = requests.post(
                            f"{BACKEND_URL}/scan/url", 
                            json={"url": url}
                        )
                        
                        if response.status_code == 200:
                            data = response.json()
                            # Get real score and remediation from your backend/security/cvss_engine.py logic
                            risk_score = data.get("cvss_score", 0)
                            summary = data.get("summary", "No summary provided.")
                            
                            col1, col2 = st.columns([1, 2])
                            with col1:
                                show_speedometer(risk_score)
                            with col2:
                                st.error(f"**Scan Result for:** {url}")
                                st.write(f"**AI Remediation:** {summary}")
                        else:
                            st.error(f"Backend Error: {response.status_code}")
                    except Exception as e:
                        st.error(f"Connection Failed: {e}")
            else:
                st.warning("Please enter a URL.")

    # --- GITHUB SCAN REAL IMPLEMENTATION ---
    elif "GitHub Scan" in active_tab:
        st.subheader("🐙 Repository Security Audit")
        repo_url = st.text_input("GitHub Repository URL", placeholder="https://github.com/user/repo")
        
        if st.button("Audit Repository", use_container_width=True):
            if repo_url:
                with st.spinner("Dispatching job to AIGIS Worker..."):
                    try:
                        # This triggers your backend/orchestrator/dispatcher.py
                        response = requests.post(
                            f"{BACKEND_URL}/scan/github", 
                            json={"repo_url": repo_url}
                        )
                        
                        if response.status_code == 202: # 202 = Accepted for processing
                            st.info("Scan started! AIGIS is currently cloning and auditing the repo.")
                            st.write("Check the 'Reports' section in a few minutes for the full PDF.")
                        else:
                            st.error("Could not start GitHub scan.")
                    except Exception as e:
                        st.error(f"Backend Connection Error: {e}")