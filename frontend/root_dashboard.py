# frontend/root_dashboard.py
import streamlit as st
from backend.database.database import SessionLocal
from backend.database.models import User

def show():
    st.title("🛠️ Root Administration Panel")
    st.info("As a Root user, you can manage user privileges and monitor system access.")
    
    db = SessionLocal()
    # List all non-root users
    users = db.query(User).filter(User.role != "root").all()
    
    st.subheader("User Permissions Management")
    
    for u in users:
        with st.expander(f"👤 {u.email} (ID: {u.id})"):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                # Current permissions selection
                available_services = ["file_scan", "link_scan", "github_scan"]
                updated_perms = st.multiselect(
                    "Assign Services",
                    available_services,
                    default=u.permissions,
                    key=f"perms_{u.id}"
                )
            
            with col2:
                st.write("") # Spacer
                if st.button("Update Access", key=f"btn_{u.id}"):
                    u.permissions = updated_perms
                    db.commit()
                    st.success(f"Updated {u.email}")
                    time.sleep(0.5)
                    st.rerun()

    db.close()