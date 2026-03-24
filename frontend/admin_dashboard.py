import streamlit as st
import requests
import pandas as pd

BACKEND_URL = "http://backend:8000"


def auth_headers():
    return {"Authorization": f"Bearer {st.session_state.token}"}


def show():
    st.title("⚙️ A.I.G.I.S — Admin Panel")
    st.caption(
        f"Logged in as **{st.session_state.username}** (Administrator)"
    )

    page = st.sidebar.radio(
        "Admin Navigation",
        [
            "🏠 Overview",
            "📁 File Scan",
            "🌐 URL Scan",
            "📦 Repository Scan",
            "📜 My Reports",
            "👥 Users",
            "📊 All Scans",
            "📄 All Reports"
        ]
    )

    # ── Scan pages shared from user_dashboard ─────────────────────────────────
    if page == "📁 File Scan":
        from user_dashboard import page_file_scan, show_active_jobs_banner
        show_active_jobs_banner()
        page_file_scan()
        return

    if page == "🌐 URL Scan":
        from user_dashboard import page_url_scan, show_active_jobs_banner
        show_active_jobs_banner()
        page_url_scan()
        return

    if page == "📦 Repository Scan":
        from user_dashboard import page_repo_scan, show_active_jobs_banner
        show_active_jobs_banner()
        page_repo_scan()
        return

    if page == "📜 My Reports":
        from user_dashboard import page_my_reports, show_active_jobs_banner
        show_active_jobs_banner()
        page_my_reports()
        return

    # ── Overview ──────────────────────────────────────────────────────────────
    if page == "🏠 Overview":
        from user_dashboard import show_active_jobs_banner
        show_active_jobs_banner()

        st.subheader("System Overview")
        col1, col2, col3 = st.columns(3)

        try:
            r = requests.get(
                f"{BACKEND_URL}/api/admin/users",
                headers=auth_headers(), timeout=10
            )
            col1.metric(
                "👥 Total Users",
                len(r.json()) if r.status_code == 200 else "—"
            )
        except Exception:
            col1.metric("👥 Total Users", "—")

        try:
            r = requests.get(
                f"{BACKEND_URL}/api/admin/reports",
                headers=auth_headers(), timeout=10
            )
            col2.metric(
                "📄 Total Reports",
                len(r.json()) if r.status_code == 200 else "—"
            )
        except Exception:
            col2.metric("📄 Total Reports", "—")

        try:
            r = requests.get(
                f"{BACKEND_URL}/api/admin/scans",
                headers=auth_headers(), timeout=10
            )
            data = r.json() if r.status_code == 200 else []
            total_scans = sum(len(g.get("scans", [])) for g in data)
            col3.metric("🔍 Total Scans", total_scans)
        except Exception:
            col3.metric("🔍 Total Scans", "—")

        st.markdown("---")

        st.subheader("🕐 Recent Activity")
        try:
            r = requests.get(
                f"{BACKEND_URL}/api/admin/reports",
                headers=auth_headers(), timeout=10
            )
            if r.status_code == 200:
                recent = r.json()[:5]
                if recent:
                    for item in recent:
                        scan_type = item.get("scan_type", "file").upper()
                        target = item.get("target", "N/A")
                        created = (
                            item.get("created_at", "")[:19].replace("T", " ")
                        )
                        vuln_count = item.get("vulnerability_count", 0)
                        highest = item.get("highest_severity", "none")
                        username = item.get("username", "unknown")
                        st.markdown(
                            f"- `[{scan_type}]` **{username}** — "
                            f"{target[:40]} — **{vuln_count} vulns** — "
                            f"`{highest}` — {created}"
                        )
                else:
                    st.info("No activity yet.")
        except Exception:
            st.warning("Could not load recent activity.")

        st.markdown("---")
        st.markdown("""
        **Admin capabilities:**
        - Run file, URL, and repository scans
        - View and manage all registered users
        - View all scan jobs across all users grouped by user
        - Download any report from any user
        - Delete user accounts
        """)

    # ── Users ─────────────────────────────────────────────────────────────────
    elif page == "👥 Users":
        st.subheader("Registered Users")
        try:
            resp = requests.get(
                f"{BACKEND_URL}/api/admin/users",
                headers=auth_headers(), timeout=10
            )
            if resp.status_code == 401:
                st.error("Session expired.")
                st.session_state.clear()
                st.rerun()
            elif resp.status_code == 403:
                st.error("Admin access required.")
            elif resp.status_code == 200:
                users = resp.json()
                if not users:
                    st.info("No users registered.")
                else:
                    st.caption(f"Total users: **{len(users)}**")
                    search = st.text_input(
                        "🔍 Search by username",
                        placeholder="Type to filter..."
                    )
                    filtered = (
                        [
                            u for u in users
                            if search.lower() in
                            u.get("username", "").lower()
                        ]
                        if search else users
                    )
                    for u in filtered:
                        uid = u.get("id")
                        uname = u.get("username", "unknown")
                        role = u.get("role", "user")
                        created = (
                            u.get("created_at", "")[:19].replace("T", " ")
                        )
                        col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                        col1.write(f"**{uname}**")
                        col2.write(f"`{role.upper()}`")
                        col3.write(created)
                        if uname != st.session_state.username:
                            if col4.button(
                                "🗑️",
                                key=f"del_{uid}",
                                help=f"Delete {uname}"
                            ):
                                del_resp = requests.delete(
                                    f"{BACKEND_URL}/api/admin/users/{uid}",
                                    headers=auth_headers(), timeout=10
                                )
                                if del_resp.status_code == 200:
                                    st.success(f"User '{uname}' deleted.")
                                    st.rerun()
                                else:
                                    st.error(
                                        f"Delete failed: {del_resp.text}"
                                    )
                        else:
                            col4.caption("(you)")
            else:
                st.error(f"Failed to load users: {resp.text}")
        except requests.exceptions.ConnectionError:
            st.error("Cannot connect to backend.")
        except Exception as e:
            st.error(f"Error: {e}")

    # ── All Scans — grouped by user ────────────────────────────────────────────
    elif page == "📊 All Scans":
        st.subheader("All Scan Jobs")
        st.caption(
            "Scans are grouped by user. "
            "Expand each user to see their scans."
        )
        try:
            resp = requests.get(
                f"{BACKEND_URL}/api/admin/scans",
                headers=auth_headers(), timeout=10
            )
            if resp.status_code == 401:
                st.error("Session expired.")
                st.session_state.clear()
                st.rerun()
            elif resp.status_code == 200:
                grouped = resp.json()

                if not grouped or all(
                    len(g.get("scans", [])) == 0 for g in grouped
                ):
                    st.info(
                        "No scan jobs found. "
                        "Scans will appear here after users run them."
                    )
                else:
                    total = sum(
                        len(g.get("scans", [])) for g in grouped
                    )
                    st.caption(
                        f"Total scan jobs across all users: **{total}**"
                    )

                    for group in grouped:
                        username = group.get("username", "unknown")
                        scans = group.get("scans", [])
                        if not scans:
                            continue

                        with st.expander(
                            f"👤 **{username}** — {len(scans)} scan(s)",
                            expanded=True
                        ):
                            all_statuses = list(
                                set(s.get("status", "unknown") for s in scans)
                            )
                            selected = st.selectbox(
                                "Filter by status",
                                ["All"] + all_statuses,
                                key=f"filter_{username}"
                            )
                            filtered = (
                                scans if selected == "All"
                                else [
                                    s for s in scans
                                    if s.get("status") == selected
                                ]
                            )

                            df = pd.DataFrame(filtered)
                            if "created_at" in df.columns:
                                df["created_at"] = pd.to_datetime(
                                    df["created_at"]
                                ).dt.strftime("%Y-%m-%d %H:%M")

                            display_cols = [
                                c for c in
                                [
                                    "input_name", "input_type",
                                    "status", "created_at"
                                ]
                                if c in df.columns
                            ]
                            st.dataframe(
                                df[display_cols],
                                use_container_width=True,
                                hide_index=True
                            )
            else:
                st.error(f"Failed to load scans: {resp.text}")
        except requests.exceptions.ConnectionError:
            st.error("Cannot connect to backend.")
        except Exception as e:
            st.error(f"Error: {e}")

    # ── All Reports ───────────────────────────────────────────────────────────
    elif page == "📄 All Reports":
        st.subheader("All Reports")
        try:
            resp = requests.get(
                f"{BACKEND_URL}/api/admin/reports",
                headers=auth_headers(), timeout=10
            )
            if resp.status_code == 401:
                st.error("Session expired.")
                st.session_state.clear()
                st.rerun()
            elif resp.status_code == 200:
                reports = resp.json()
                if not reports:
                    st.info("No reports found.")
                else:
                    st.caption(f"Total reports: **{len(reports)}**")

                    scan_types = list(
                        set(r.get("scan_type", "file") for r in reports)
                    )
                    selected_type = st.selectbox(
                        "Filter by scan type",
                        ["All"] + [t.upper() for t in scan_types]
                    )
                    filtered = (
                        reports if selected_type == "All"
                        else [
                            r for r in reports
                            if r.get("scan_type", "").upper() == selected_type
                        ]
                    )

                    for r in filtered:
                        job_id = r.get("job_id", "")
                        scan_type = r.get("scan_type", "file").upper()
                        target = r.get("target", "N/A")
                        created = (
                            r.get("created_at", "")[:19].replace("T", " ")
                        )
                        vuln_count = r.get("vulnerability_count", 0)
                        threat = r.get("threat_score", 0.0)
                        highest = r.get("highest_severity", "none")
                        username = r.get("username", "unknown")

                        with st.expander(
                            f"[{scan_type}] {target[:45]} — "
                            f"{vuln_count} vulns — {username} — {created}"
                        ):
                            col1, col2, col3, col4 = st.columns(4)
                            col1.metric("Vulnerabilities", vuln_count)
                            col2.metric("Threat Score", f"{threat:.0f}%")
                            col3.metric(
                                "Highest", highest.capitalize()
                            )
                            col4.metric("User", username)

                            st.caption(f"Job ID: `{job_id}`")
                            try:
                                dl_resp = requests.get(
                                    f"{BACKEND_URL}/api/admin"
                                    f"/reports/{job_id}/download",
                                    headers=auth_headers(),
                                    timeout=30
                                )
                                if dl_resp.status_code == 200:
                                    st.download_button(
                                        label="📥 Download PDF",
                                        data=dl_resp.content,
                                        file_name=(
                                            f"AIGIS_{job_id[:8]}.pdf"
                                        ),
                                        mime="application/pdf",
                                        key=f"admin_dl_{job_id}"
                                    )
                                else:
                                    st.warning("Report file not available.")
                            except Exception:
                                st.warning("Could not fetch report file.")
            else:
                st.error(f"Failed to load reports: {resp.text}")
        except requests.exceptions.ConnectionError:
            st.error("Cannot connect to backend.")
        except Exception as e:
            st.error(f"Error: {e}")