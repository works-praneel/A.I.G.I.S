import streamlit as st
import time
import sys
import os

# --- 1. PATH RESOLUTION ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- 2. INTERNAL IMPORTS ---
try:
    from backend.database.database import SessionLocal
    from backend.database.models import User
    from backend.auth.password import verify_password, hash_password 
except ImportError as e:
    st.error(f"Import Error: {e}. Ensure you are running from the A.I.G.I.S root folder.")

# --- 3. DATABASE HELPER ---
def get_db():
    db = SessionLocal()
    try:
        return db
    finally:
        db.close()

# --- 4. STREAMLIT CONFIGURATION ---
st.set_page_config(page_title="AIGIS Security Portal", page_icon="🛡️", layout="wide")

if 'logged_in' not in st.session_state:
    st.session_state.update({
        'logged_in': False, 
        'user_email': "", 
        'role': "", 
        'perms': [],
        'prefill_email': ""
    })

# --- 5. AUTHENTICATION HANDLER ---
def handle_login(email, password):
    db = get_db()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user and verify_password(password[:72], user.hashed_password):
            st.session_state.update({
                'logged_in': True,
                'user_email': user.email,
                'role': user.role,
                'perms': user.permissions if user.permissions else []
            })
            st.success(f"Access Granted. Loading dashboard...")
            time.sleep(1)
            st.rerun()
        else:
            st.error("Invalid email or password.")
    except Exception as err:
        st.error(f"Database Connection Error: {err}")

# --- 6. MAIN UI LOGIC ---
if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        logo_path = os.path.join(os.path.dirname(__file__), 'assets', 'logo.png')
        if os.path.exists(logo_path):
            st.image(logo_path, use_container_width=True)
        else:
            st.title("🛡️ A.I.G.I.S")
            st.caption("Autonomous Guard & Inspection System")

    tab1, tab2 = st.tabs(["🔐 Login", "📝 Create Account"])
    
    with tab1:
        if st.button("🙋 Prepare Root Login", use_container_width=True):
            st.session_state.prefill_email = "subhaprakashjana@gmail.com"
            st.rerun() 

        with st.form("login_form"):
            e = st.text_input("Email Address", value=st.session_state.prefill_email)
            p = st.text_input("Password", type="password")
            if st.form_submit_button("Sign In", use_container_width=True):
                handle_login(e, p)
                
    with tab2:
        with st.form("signup_form"):
            ne = st.text_input("New Email")
            np = st.text_input("New Password", type="password")
            confirm_p = st.text_input("Confirm Password", type="password")
            if st.form_submit_button("Register Account", use_container_width=True):
                if np == confirm_p and np:
                    db = get_db()
                    if db.query(User).filter(User.email == ne).first():
                        st.error("Email already registered.")
                    else:
                        new_user = User(email=ne, hashed_password=hash_password(np[:72]), role="user", permissions=["link_scan"])
                        db.add(new_user)
                        db.commit()
                        st.success("Account created! You can now log in.")
                else:
                    st.error("Passwords do not match.")

# --- 7. DASHBOARD ROUTING ---
else:
    st.sidebar.title("AIGIS Engine")
    if st.sidebar.button("🚪 Logout", use_container_width=True):
        st.session_state.clear()
        st.rerun()

    try:
        if st.session_state.role == "root":
            from frontend import root_dashboard
            root_dashboard.show()
        else:
            from frontend import user_dashboard
            user_dashboard.show()
    except Exception as err:
        st.error(f"Dashboard Load Error: {err}")