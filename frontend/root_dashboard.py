import streamlit as st
import time 
from backend.database.database import SessionLocal
from backend.database.models import User

def show():
    st.header("⚒️ Root Administration Panel")
    st.info("Manage user privileges and monitor system access.")
    
    db = SessionLocal()
    try:
        users = db.query(User).all()
        for user in users:
            with st.expander(f"👤 {user.email} (ID: {user.id})"):
                available_services = ["file_scan", "link_scan", "github_scan", "admin_panel"]
                current_perms = user.permissions if user.permissions else []
                
                new_perms = st.multiselect("Assign Services", available_services, default=current_perms, key=f"perms_{user.id}")
                
                if st.button("Update Access", key=f"btn_{user.id}"):
                    user.permissions = new_perms
                    db.commit()
                    st.toast(f"Updated {user.email}", icon="✅")
                    time.sleep(1)
                    st.rerun()
    except Exception as e:
        st.error(f"Database Error: {e}")
    finally:
        db.close()