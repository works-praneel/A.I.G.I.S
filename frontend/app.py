import streamlit as st
import time
import sys
import os

# --- 1. PATH RESOLUTION ---
# Ensures the app can find the 'backend' folder when running inside Docker
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- 2. INTERNAL IMPORTS ---
try:
    from backend.database.database import SessionLocal
    from backend.database.models import User
    from backend.auth.password import verify_password, hash_password 
except ImportError as e:
    st.error(f"Import Error: {e}. Run from the project root folder.")

# --- 3. DATABASE HELPER ---
def get_db():
    db = SessionLocal()
    try:
        return db
    finally:
        db.close()

# --- 4. STREAMLIT CONFIGURATION ---
st.set_page_config(
    page_title="AIGIS Security Portal", 
    page_icon="🛡️",
    layout="wide"
)

# Initialize Session State
if 'logged_in' not in st.session_state:
    st.session_state.update({
        'logged_in': False, 
        'user_email': "", 
        'role': "", 
        'perms': [],
        'prefill_email': "" # For the Dev Shortcut
    })

# --- 5. AUTHENTICATION HANDLER ---
def handle_login(email, password):
    db = get_db()
    try:
        user = db.query(User).filter(User.email == email).first()
        
        # Security Note: [:72] handles the Bcrypt length limitation
        if user and verify_password(password[:72], user.hashed_password):
            st.session_state.update({
                'logged_in': True,
                'user_email': user.email,
                'role': user.role,
                'perms': user.permissions if user.permissions else []
            })
            st.success(f"Access Granted. Loading {user.role} dashboard...")
            time.sleep(1)
            st.rerun()
        else:
            st.error("Invalid email or password. Please try again.")
    except Exception as err:
        st.error(f"Connection Error: {err}")
    finally:
        db.close()

# --- 6. MAIN UI LOGIC ---
if not st.session_state.logged_in:
    st.title("🛡️ A.I.G.I.S Authentication")
    
    tab1, tab2 = st.tabs(["🔐 Login", "📝 Create Account"])
    
    # --- LOGIN TAB ---
    with tab1:
        # DEVELOPMENT SHORTCUT
        st.info("Development Mode: Use the shortcut below to fill the login fields.")
        if st.button("🙋 Prepare Root Login", use_container_width=True):
            st.session_state.prefill_email = "subhaprakashjana@gmail.com"
            st.rerun() 

        st.markdown("---") 

        # ACTUAL FORM
        with st.form("login_form"):
            # Email is pre-filled if the button above was clicked
            e = st.text_input("Email Address", value=st.session_state.prefill_email)
            p = st.text_input("Password", type="password", placeholder="Enter your secret key...")
            
            if st.form_submit_button("Sign In", use_container_width=True):
                if e and p:
                    handle_login(e, p)
                else:
                    st.warning("Please enter both email and password.")
                
    # --- REGISTRATION TAB ---
    with tab2:
        with st.form("signup_form"):
            st.write("Register for the AIGIS Testing Framework")
            ne = st.text_input("New Email")
            np = st.text_input("New Password", type="password")
            confirm_p = st.text_input("Confirm Password", type="password")
            
            if st.form_submit_button("Register Account", use_container_width=True):
                if np == confirm_p:
                    db = get_db()
                    try:
                        if db.query(User).filter(User.email == ne).first():
                            st.error("Email already exists.")
                        else:
                            # Registration safety truncation
                            hashed_pw = hash_password(np[:72]) 
                            new_user = User(
                                email=ne, 
                                hashed_password=hashed_pw, 
                                role="user", 
                                permissions=["link_scan"] 
                            )
                            db.add(new_user)
                            db.commit()
                            st.success("Account created! Switch to Login tab to enter.")
                    except Exception as err:
                        st.error(f"Error: {err}")
                    finally:
                        db.close()
                else:
                    st.error("Passwords do not match.")

# --- 7. DASHBOARD ROUTING ---
else:
    # Sidebar Info
    st.sidebar.title("AIGIS Engine")
    st.sidebar.markdown(f"**Logged in as:** `{st.session_state.user_email}`")
    st.sidebar.markdown(f"**Access Level:** :red[{st.session_state.role.upper()}]")
    
    if st.sidebar.button("🚪 Logout", use_container_width=True):
        st.session_state.clear()
        st.rerun()

    # Route based on Role
    try:
        if st.session_state.role == "root":
            from frontend import root_dashboard
            root_dashboard.show()
        else:
            from frontend import user_dashboard
            user_dashboard.show()
    except Exception as err:
        st.error(f"Dashboard Load Error: {err}")