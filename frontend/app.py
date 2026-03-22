import streamlit as st
import requests
import time
import os

BACKEND_URL = "http://backend:8000"

st.set_page_config(
    page_title="A.I.G.I.S Security Portal",
    page_icon="🛡️",
    layout="wide"
)

if "logged_in" not in st.session_state:
    st.session_state.update({
        "logged_in": False,
        "token": "",
        "username": "",
        "role": "",
        "register_done": False,
    })


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
            # Rerun clears the form naturally since the login
            # page is no longer rendered
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
            # Set flag so the form reruns and clears its fields
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

        # Register tab comes first now
        # After register_done is set, rerun clears the form
        # because Streamlit rebuilds the widget tree from scratch
        tab_register, tab_login = st.tabs(["📝 Register", "🔐 Login"])

        with tab_register:
            st.caption(
                "The first account registered becomes Admin. "
                "All subsequent accounts are standard users."
            )

            # Using a key tied to register_done forces Streamlit to
            # rebuild the form with empty fields after a successful
            # registration — without this the fields stay filled
            form_key = (
                "register_form_clean"
                if st.session_state.register_done
                else "register_form"
            )

            # Show success banner if just registered
            if st.session_state.register_done:
                st.success(
                    "✅ Account created! Switch to the Login tab to sign in."
                )
                # Reset the flag so the banner only shows once
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
            # login_attempt key forces a fresh form after each failed
            # attempt if you want to clear it — for now the form clears
            # naturally on successful login via st.rerun()
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                if st.form_submit_button(
                    "Sign In", use_container_width=True
                ):
                    handle_login(username, password)

# ── Logged in ──────────────────────────────────────────────────────────────────
else:
    with st.sidebar:
        st.markdown(f"**User:** {st.session_state.username}")
        st.markdown(f"**Role:** `{st.session_state.role.upper()}`")
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.clear()
            st.rerun()

    if st.session_state.role == "admin":
        from admin_dashboard import show as show_admin
        show_admin()
    else:
        from user_dashboard import show as show_user
        show_user()