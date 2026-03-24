import streamlit as st
import requests
import time
import os
import json
from streamlit_cookies_manager import EncryptedCookieManager

BACKEND_URL = "http://backend:8000"

st.set_page_config(
    page_title="A.I.G.I.S Security Portal",
    page_icon="🛡️",
    layout="wide"
)

# ── 1. Initialize Cookie Manager ───────────────────────────────────────────────
cookies = EncryptedCookieManager(
    prefix="aigis",
    password="A_VERY_SECURE_STATIC_PASSWORD_FOR_DEMO"
)

# If the browser blocks the cookie component, give the user an escape hatch
if not cookies.ready():
    st.markdown("<br><br><br><h3 style='text-align: center;'>🛡️ Restoring A.I.G.I.S Session...</h3>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #888;'>Reading secure local vault...</p>", unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    _, col, _ = st.columns([1, 2, 1])
    if col.button("⚠️ Click here if stuck loading (Browser blocking cookies)", use_container_width=True):
        st.session_state.bypass_cookies = True
        st.rerun()
        
    if not st.session_state.get("bypass_cookies", False):
        st.stop()

st.session_state.cookies = cookies


# ── 2. Sync Cookies to Session State ───────────────────────────────────────────
if "logged_in" not in st.session_state:
    saved_auth = cookies.get("auth_data") if cookies.ready() else None
    saved_jobs = cookies.get("active_jobs") if cookies.ready() else None

    if saved_auth:
        try:
            auth_data = json.loads(saved_auth)
            st.session_state.update({
                "logged_in": True,
                "token": auth_data.get("token", ""),
                "username": auth_data.get("username", ""),
                "role": auth_data.get("role", ""),
                "register_done": False,
            })
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


def auth_headers():
    return {"Authorization": f"Bearer {st.session_state.token}"}


def handle_login(username: str, password: str):
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
            st.rerun()
            
        elif response.status_code == 401:
            st.error("Incorrect username or password.")
        else:
            st.error(f"Login failed: {response.text}")
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to backend. Is the server running?")
    except Exception as e:
        st.error(f"Unexpected error: {e}")


def handle_register(username: str, password: str, confirm: str):
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
                st.success(
                    "✅ Admin account created! You are the first user. "
                    "Please log in."
                )
            else:
                st.success("✅ Account created! Please log in.")
            st.session_state.register_done = True
            st.rerun()
        elif response.status_code == 400:
            st.error("Username already registered.")
        else:
            st.error(f"Registration failed: {response.text}")
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to backend.")
    except Exception as e:
        st.error(f"Unexpected error: {e}")


# ── Not logged in ──────────────────────────────────────────────────────────────
if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        logo_path = os.path.join(
            os.path.dirname(__file__), "assets", "logo.png"
        )
        if os.path.exists(logo_path):
            st.image(logo_path, use_container_width=True)
        else:
            st.markdown(
                "<h1 style='text-align:center;'>🛡️ A.I.G.I.S</h1>",
                unsafe_allow_html=True
            )
            st.markdown(
                "<p style='text-align:center;color:#aaa;'>"
                "Autonomous Intelligence & Guard Inspection System"
                "</p>",
                unsafe_allow_html=True
            )

        st.markdown("<br>", unsafe_allow_html=True)

        tab_register, tab_login = st.tabs(["📝 Register", "🔐 Login"])

        with tab_register:
            st.caption(
                "The first account registered becomes Admin. "
                "All subsequent accounts are standard users."
            )

            form_key = (
                "register_form_clean"
                if st.session_state.register_done
                else "register_form"
            )

            if st.session_state.register_done:
                st.success(
                    "✅ Account created! Switch to the Login tab to sign in."
                )
                st.session_state.register_done = False

            with st.form(form_key):
                new_username = st.text_input("Username")
                new_password = st.text_input("Password", type="password")
                confirm_password = st.text_input(
                    "Confirm Password", type="password"
                )
                if st.form_submit_button(
                    "Create Account", use_container_width=True
                ):
                    handle_register(
                        new_username, new_password, confirm_password
                    )

        with tab_login:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                if st.form_submit_button(
                    "Sign In", use_container_width=True
                ):
                    handle_login(username, password)

# ── Logged in ──────────────────────────────────────────────────────────────────
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
        # Attach the logic to the on_click parameter
        st.button("🚪 Logout", use_container_width=True, on_click=perform_logout)

    if st.session_state.role == "admin":
        from admin_dashboard import show as show_admin
        show_admin()
    else:
        from user_dashboard import show as show_user
        show_user()