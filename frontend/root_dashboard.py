import streamlit as st
import time  # <--- CRITICAL: Fixes your 'time is not defined' error
from backend.database.database import SessionLocal
from backend.database.models import User

def show():
    st.header("⚒️ Root Administration Panel")
    st.info("As a Root user, you can manage user privileges and monitor system access.")
    
    st.subheader("User Permissions Management")
    
    db = SessionLocal()
    try:
        users = db.query(User).all()
        for user in users:
            # Create an expander for each user
            with st.expander(f"👤 {user.email} (ID: {user.id})"):
                # Multi-select for services
                available_services = ["file_scan", "link_scan", "github_scan", "admin_panel"]
                current_perms = user.permissions if user.permissions else []
                
                new_perms = st.multiselect(
                    "Assign Services", 
                    available_services, 
                    default=current_perms,
                    key=f"perms_{user.id}"
                )
                
                if st.button("Update Access", key=f"btn_{user.id}"):
                    user.permissions = new_perms
                    db.commit()
                    st.toast(f"Updated permissions for {user.email}", icon="✅")
                    time.sleep(1) # Now this works because we imported time
                    st.rerun()
    except Exception as e:
        st.error(f"Database Error: {e}")
    finally:
        db.close()