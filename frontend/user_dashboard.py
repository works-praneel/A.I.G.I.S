import streamlit as st
import requests
import time
import os

# --- CONSTANTS ---
# CRITICAL: Using 'backend' (service name) for Docker-to-Docker networking
BACKEND_URL = "http://backend:8000/api/v1" 

def show_speedometer(score, label="THREAT LEVEL"):
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

def apply_custom_styles():
    st.markdown("""
        <style>
        .stMetric {
            background-color: #1e2130;
            padding: 15px;
            border-radius: 10px;
            border: 1px solid #3d425c;
        }
        [data-testid="stExpander"] {
            border: 1px solid #00d4ff;
            border-radius: 10px;
            background-color: #0e1117;
        }
        h1, h2, h3 {
            color: #00d4ff;
            text-shadow: 0px 0px 10px rgba(0, 212, 255, 0.3);
        }
        .stCodeBlock {
            border: 1px solid #3d425c;
        }
        </style>
    """, unsafe_allow_html=True)

def show():
    apply_custom_styles()
    perms = st.session_state.get('perms', [])
    
    # --- SIDEBAR NAVIGATION ---
    tabs = ["Overview"]
    if "file_scan" in perms: tabs.append("📁 File Scan")
    if "link_scan" in perms: tabs.append("🔗 Link Scan")
    if "github_scan" in perms: tabs.append("🐙 GitHub Scan")
    
    active_tab = st.sidebar.radio("Navigation", tabs)

    # --- 1. OVERVIEW SECTION ---
    if active_tab == "Overview":
        # Professional Support Header
        with st.expander("📞 Technical Support & Core Team"):
            c1, c2, c3, c4 = st.columns(4)
            c1.info("**Subh**\n\n7797416720")
            c2.info("**Praneel**\n\n93549 73114")
            c3.info("**Animesh**\n\n62029 72581")
            c4.info("**Akshan**\n\n94677 45887")

        col_text, col_logo = st.columns([2, 1])
        with col_text:
            st.title("🛡️ A.I.G.I.S Analysis Engine")
            st.subheader("Autonomous Guard & Inspection System")
            st.markdown("""
            Welcome to the future of **Cloud-Native Security**. A.I.G.I.S is an autonomous, 
            multi-modal testing framework designed to intercept threats across your entire stack.
            
            ### 🚀 Intelligent Security Modules
            * **Deep File Inspection:** Scans binaries and scripts in isolated sandboxes.
            * **URL Reputation:** Real-time threat intelligence for web endpoints.
            * **Repo Auditing:** Automated GitHub scanning for secrets & vulnerabilities.
            * **AI Remediation:** Suggestions and vulnerability patching via Llama3.
            """)
        
        with col_logo:
            logo_path = os.path.join(os.path.dirname(__file__), 'assets', 'logo.png')
            if os.path.exists(logo_path):
                st.image(logo_path, use_container_width=True)

        st.markdown("---")
        st.markdown("### 📊 Engine Operations")
        m1, m2, m3 = st.columns(3)
        m1.metric("Engine Status", "Online", delta="Stable")
        m2.metric("Active Scanners", len(tabs)-1, delta="Operational")
        m3.metric("AI Model", "Llama3", delta="Ready")

    # --- 2. FILE SCAN SECTION ---
    elif "File Scan" in active_tab:
        st.header("📁 Static File Analysis")
        st.write("Upload source code or binaries to execute within an isolated A.I.G.I.S Sandbox.")
        
        uploaded_file = st.file_uploader(
            "Upload file for inspection", 
            type=['exe', 'pdf', 'zip', 'py', 'java', 'js', 'cpp', 'sh']
        )
        
        if uploaded_file:
            # Code Preview for Source Files
            extension = uploaded_file.name.split('.')[-1].lower()
            if extension in ['py', 'java', 'js', 'cpp', 'sh']:
                with st.expander("🔍 Source Code Preview", expanded=True):
                    try:
                        content = uploaded_file.getvalue().decode("utf-8")
                        st.code(content, language=extension)
                    except Exception:
                        st.warning("Could not render code preview (check file encoding).")

            if st.button("Start Sandbox Scan", use_container_width=True):
                with st.spinner(f"AIGIS Sandbox is analyzing {uploaded_file.name}..."):
                    files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
                    try:
                        response = requests.post(f"{BACKEND_URL}/scan/file", files=files)
                        if response.status_code == 200:
                            data = response.json()
                            score = data.get("risk_score", 0)
                            
                            col1, col2 = st.columns([1, 2])
                            with col1:
                                show_speedometer(score, "VULNERABILITY SCORE")
                            with col2:
                                st.subheader("Analysis Report")
                                st.info(f"**Target:** {uploaded_file.name}")
                                st.write(f"**AI Summary:** {data.get('summary', 'Analysis complete.')}")
                                st.write(f"**Details:** {data.get('report', 'No malicious patterns detected.')}")
                        else:
                            st.error(f"Engine Error: {response.status_code}")
                    except Exception as e:
                        # This will now clearly show if it's still a connection issue
                        st.error(f"Backend Connection Error: {e}")
        else:
            st.info("Please upload a file to begin the analysis.")

    # --- 3. LINK SCAN SECTION ---
    elif "Link Scan" in active_tab:
        st.header("🔗 URL Threat Analysis")
        url = st.text_input("Enter target URL", placeholder="https://example.com")
        if st.button("Initiate URL Scan", use_container_width=True):
            if url:
                with st.spinner("Consulting AIGIS Threat Intel..."):
                    try:
                        response = requests.post(f"{BACKEND_URL}/scan/url", json={"url": url})
                        if response.status_code == 200:
                            data = response.json()
                            risk_score = data.get("cvss_score", 0)
                            col1, col2 = st.columns([1, 2])
                            with col1: show_speedometer(risk_score)
                            with col2:
                                st.error(f"**Analysis for:** {url}")
                                st.write(f"**AI Remediation:** {data.get('summary', 'Safe to visit.')}")
                    except Exception as e:
                        st.error(f"Connection Failed: {e}")

    # --- 4. GITHUB SCAN SECTION ---
    elif "GitHub Scan" in active_tab:
        st.header("🐙 Repository Security Audit")
        repo_url = st.text_input("GitHub Repo URL", placeholder="https://github.com/user/repo")
        if st.button("Audit Repository", use_container_width=True):
            if repo_url:
                with st.spinner("Cloning and auditing..."):
                    try:
                        response = requests.post(f"{BACKEND_URL}/scan/github", json={"repo_url": repo_url})
                        if response.status_code == 202:
                            st.success("Audit Job Dispatched! The PDF report will be ready shortly.")
                    except Exception as e:
                        st.error(f"Orchestrator Offline: {e}")