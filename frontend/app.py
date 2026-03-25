import streamlit as st
import requests
import json
import os
from streamlit_cookies_manager import EncryptedCookieManager

BACKEND_URL = "http://backend:8000"

st.set_page_config(
    page_title="A.I.G.I.S Security Portal",
    page_icon="🛡️",
    layout="wide"
)

# ── 1. Initialize Cookie Manager ───────────────────────────────────────────────
if "cookie_manager" not in st.session_state:
    st.session_state.cookie_manager = EncryptedCookieManager(
        prefix="aigis",
        password="A_VERY_SECURE_STATIC_PASSWORD_FOR_DEMO"
    )
    
cookies = st.session_state.cookie_manager
# We no longer pause the app or show a bypass button! 
# The app will smoothly render the Login screen while cookies load in the background.

# ── 2. Sync Cookies & Validate Token ───────────────────────────────────────────
if "logged_in" not in st.session_state:
    saved_auth = cookies.get("auth_data") if cookies.ready() else None
    saved_jobs = cookies.get("active_jobs") if cookies.ready() else None

    if saved_auth:
        try:
            auth_data = json.loads(saved_auth)
            token = auth_data.get("token", "")
            
            # --- VERIFY THE DATABASE IS STILL ALIVE ---
            try:
                verify_resp = requests.get(
                    f"{BACKEND_URL}/api/reports/",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5
                )
                if verify_resp.status_code == 401:
                    # Database wiped! Kill the cookie and force a fresh start.
                    if cookies.ready():
                        cookies["auth_data"] = ""
                        cookies["active_jobs"] = ""
                        cookies.save()
                    st.session_state.update({
                        "logged_in": False,
                        "token": "",
                        "username": "",
                        "role": "",
                        "register_done": False,
                    })
                    # REMOVED st.rerun() - allowing the script to naturally finish
                    # ensures the browser successfully receives the cookie wipe command!
                else:
                    st.session_state.update({
                        "logged_in": True,
                        "token": token,
                        "username": auth_data.get("username", ""),
                        "role": auth_data.get("role", ""),
                        "register_done": False,
                    })
            except requests.exceptions.ConnectionError:
                pass
        except Exception:
            pass
    else:
        st.session_state.update({
            "logged_in": False,
            "token": "",
            "username": "",
            "role": "",
            "register_done": False,
        })

    if saved_jobs:
        try:
            st.session_state.active_jobs = json.loads(saved_jobs)
        except Exception:
            st.session_state.active_jobs = {}
    else:
        st.session_state.active_jobs = {}


# ── 3. Authentication Callbacks ────────────────────────────────────────────────
# Using callbacks ensures state and cookies are updated safely before the UI renders.

def process_login():
    username = st.session_state.get("login_usr", "")
    password = st.session_state.get("login_pwd", "")
    if not username or not password:
        st.error("Please enter your username and password.")
        return
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/auth/login",
            data={"username": username, "password": password},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            st.session_state.update({
                "logged_in": True,
                "token": data["access_token"],
                "username": data.get("username", username),
                "role": data.get("role", "user"),
            })
            if cookies.ready():
                cookies["auth_data"] = json.dumps({
                    "token": data["access_token"],
                    "username": data.get("username", username),
                    "role": data.get("role", "user"),
                })
                cookies.save()
        elif response.status_code == 401:
            st.error("Incorrect username or password.")
        else:
            st.error(f"Login failed: {response.text}")
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to backend. Is the server running?")
    except Exception as e:
        st.error(f"Unexpected error: {e}")


def process_register():
    username = st.session_state.get("reg_usr", "")
    password = st.session_state.get("reg_pwd", "")
    confirm = st.session_state.get("reg_conf", "")
    if not username or not password:
        st.error("Username and password are required.")
        return
    if password != confirm:
        st.error("Passwords do not match.")
        return
    if len(password) < 6:
        st.error("Password must be at least 6 characters.")
        return
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/auth/register",
            json={"username": username, "password": password},
            timeout=10
        )
        if response.status_code == 201:
            data = response.json()
            role = data.get("role", "user")
            if role == "admin":
                st.success("✅ Admin account created! You are the first user. Please log in.")
            else:
                st.success("✅ Account created! Please log in.")
            st.session_state.register_done = True
        elif response.status_code == 400:
            st.error("Username already registered.")
        else:
            st.error(f"Registration failed: {response.text}")
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to backend.")
    except Exception as e:
        st.error(f"Unexpected error: {e}")


# ── 4. Main UI Router ──────────────────────────────────────────────────────────

if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        if os.path.exists(logo_path):
            st.image(logo_path, use_container_width=True)
        else:
            st.markdown("<h1 style='text-align:center;'>🛡️ A.I.G.I.S</h1>", unsafe_allow_html=True)
            st.markdown("<p style='text-align:center;color:#aaa;'>Autonomous Intelligence & Guard Inspection System</p>", unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)

        tab_register, tab_login = st.tabs(["📝 Register", "🔐 Login"])

        with tab_register:
            st.caption("The first account registered becomes Admin. All subsequent accounts are standard users.")
            form_key = "register_form_clean" if st.session_state.register_done else "register_form"
            
            if st.session_state.register_done:
                st.success("✅ Account created! Switch to the Login tab to sign in.")
                st.session_state.register_done = False

            with st.form(form_key):
                st.text_input("Username", key="reg_usr")
                st.text_input("Password", type="password", key="reg_pwd")
                st.text_input("Confirm Password", type="password", key="reg_conf")
                st.form_submit_button("Create Account", use_container_width=True, on_click=process_register)

        with tab_login:
            with st.form("login_form"):
                st.text_input("Username", key="login_usr")
                st.text_input("Password", type="password", key="login_pwd")
                st.form_submit_button("Sign In", use_container_width=True, on_click=process_login)

else:
    def perform_logout():
        st.session_state.update({
            "logged_in": False,
            "token": "",
            "username": "",
            "role": "",
            "active_jobs": {}
        })
        if cookies.ready():
            cookies["auth_data"] = ""
            cookies["active_jobs"] = ""
            cookies.save()

    with st.sidebar:
        st.markdown(f"**User:** {st.session_state.username}")
        st.markdown(f"**Role:** `{st.session_state.role.upper()}`")
        st.markdown("---")
        st.button("🚪 Logout", use_container_width=True, on_click=perform_logout)

    if st.session_state.role == "admin":
        from admin_dashboard import show as show_admin
        show_admin()
    else:
        from user_dashboard import show as show_user
        show_user()