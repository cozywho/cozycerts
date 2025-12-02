import streamlit as st
from datetime import datetime
from io import BytesIO
import zipfile
import pandas as pd

from utils import (
    CA_CERT,
    CERTS_DIR,
    metadata,
    create_root_ca,
    get_cert_expiry,
    generate_cert,
    sign_csr,
    export_certificate,
    save_metadata,
    revoke_cert,
    _reset_ca,
    safe_name,
    load_cert_metadata,
    inspect_cert,
    fmt_expiry,
    parse_expiry
)

st.set_page_config(page_title="cozycerts", layout="centered")

st.markdown(
    """
    <style>

    /* --- Your existing button sizing --- */
    div[data-testid="column"] button,
    div[data-testid="column"] .stDownloadButton button {
        padding: 0.35rem 0.75rem;
        font-size: 0.9rem;
    }

    /* --- Force narrow window layout --- */
    .block-container {
        max-width: 700px !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        margin-left: auto !important;
        margin-right: auto !important;
    }

    </style>
    """,
    unsafe_allow_html=True,
)

st.columns([1, 4])[0].image("cprl.png", width=90)
st.title("cozycerts v2.0")

tabs = st.tabs(["Root CA", "Generate", "Metadata", "Inspect", "Reset"])

with tabs[0]:
    st.subheader("Root CA")

    if not CA_CERT.exists():
        st.error("No Root CA found. Please create one.")
        if st.button("Create Root CA"):
            create_root_ca()
            st.success("Root CA created")
            st.rerun()

    else:
        with st.expander("Details & Downloads", expanded=False):
            expiry_str, days_left, color = fmt_expiry(get_cert_expiry(CA_CERT))
            st.write(f"{color} rootCA → Expires {expiry_str} ({days_left} days left)")

            st.download_button(
                "⬇ Download Trusted Root Certificate",
                data=CA_CERT.read_bytes(),
                file_name="rootCA.crt",
                mime="application/octet-stream",
            )

            with st.expander("Install Instructions"):
                st.markdown("""
                **Fedora / Rocky / RHEL**
                ```bash
                sudo cp rootCA.crt /etc/pki/ca-trust/source/anchors/
                sudo update-ca-trust extract
                ```
                """)

    st.subheader("Certificate Dashboard")

    issued_dirs = [d for d in CERTS_DIR.iterdir() if d.is_dir()]

    if not issued_dirs:
        st.info("No certificate entries yet.")

    else:
        rows = []
        for cert_dir in issued_dirs:
            name = cert_dir.name
            crt = cert_dir / "cert.crt"
            meta = load_cert_metadata(cert_dir)
            revoked = bool(meta.get("revoked", False)) if meta else False

            expiry_raw = parse_expiry(meta, crt)
            expiry_str, days_left, color = fmt_expiry(expiry_raw)

            if revoked:
                color = "⚫"
            elif not crt.exists():
                color = "⚪"

            expiry_display = expiry_str
            days_display = f"{color} {days_left}"

            rows.append({
                "CN": name,
                "DNS": ", ".join(meta.get("dns", [])) if meta else "",
                "IP": ", ".join(meta.get("ips", [])) if meta else "",
                "Expires": expiry_display,
                "Days Left": days_display,
                "selected": False,
            })

        df = pd.DataFrame(rows)

        edited = st.data_editor(
            df,
            hide_index=True,
            column_config={
                "selected": st.column_config.CheckboxColumn("Select")
            },
            disabled=["CN", "DNS", "IP", "Expires", "Days Left"],
        )

        selected = edited[edited["selected"] == True]["CN"].tolist()

        if selected:
            selected_str = ", ".join(selected)

            action = st.selectbox(
                f"Selected Certs: {selected_str}",
                ["Download", "Export", "Revoke", "Delete"],
                key="action_choice"
            )

            if action == "Download":
                if st.button("Download Selected"):
                    buf = BytesIO()
                    with zipfile.ZipFile(buf, "w") as z:
                        for cn in selected:
                            cert_path = CERTS_DIR / cn
                            if cert_path.exists():
                                for f in cert_path.iterdir():
                                    z.write(f, arcname=f"{cn}/{f.name}")

                    st.download_button(
                        "⬇ Download ZIP",
                        data=buf.getvalue(),
                        file_name="selected_certs.zip",
                        mime="application/zip",
                    )

            elif action == "Export":
                fmt = st.selectbox(
                    "Export Format",
                    ["pem", "der", "pkcs12", "jks", "bundle"],
                    key="export_fmt"
                )

                password = ""
                if fmt in ["pkcs12", "jks"]:
                    password = st.text_input("Password", type="password")

                if st.button("Generate Export ZIP"):
                    buf = BytesIO()
                    with zipfile.ZipFile(buf, "w") as z:
                        for cn in selected:
                            out_file, msg = export_certificate(cn, fmt, password)
                            if out_file:
                                z.write(out_file, arcname=f"{cn}/{out_file.name}")

                    st.download_button(
                        "⬇ Download Export",
                        data=buf.getvalue(),
                        file_name="certs_export.zip",
                        mime="application/zip",
                    )

            elif action == "Revoke":
                st.warning("Revoking a certificate cannot be undone.")
                if st.button("Confirm Revoke"):
                    for cn in selected:
                        revoke_cert(cn)
                    st.success("Revoked.")
                    st.rerun()

            elif action == "Delete":
                st.error("This will permanently delete the certificate files.")
                if st.button("Confirm Delete"):
                    import shutil
                    for cn in selected:
                        path = CERTS_DIR / cn
                        if path.exists():
                            shutil.rmtree(path)
                    st.success("Deleted.")
                    st.rerun()


with tabs[1]:
    st.subheader("Generate New Certificate")

    cn_raw = st.text_input("Common Name (CN)")
    dns_raw = st.text_input("DNS SANs (comma-separated)")
    ip_raw = st.text_input("IP SANs (comma-separated)")
    self_sign = st.toggle("Self-sign with Root CA", value=True)

    dns_list = [x.strip() for x in dns_raw.split(",") if x.strip()]
    ip_list = [x.strip() for x in ip_raw.split(",") if x.strip()]
    cn_final = cn_raw.strip() if cn_raw else None

    if st.button("Generate"):
        key_file, csr_file, cert_file = generate_cert(
            cn_final,
            dns_list,
            ip_list,
            self_sign,
        )

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.write(key_file, arcname=key_file.name)
            z.write(csr_file, arcname=csr_file.name)
            if cert_file:
                z.write(cert_file, arcname=cert_file.name)

        st.success("Generated.")
        st.download_button("⬇ Download Bundle", buf.getvalue(), "generated_bundle.zip")


with tabs[2]:
    st.subheader("Metadata Defaults")

    text_fields = [
        ("country", "Country"),
        ("state", "State"),
        ("locality", "Locality"),
        ("org", "Organization"),
        ("ou", "Organizational Unit"),
    ]
    updates = {k: st.text_input(label, metadata[k]) for k, label in text_fields}
    updates["days"] = st.number_input("Validity (days)", min_value=1, value=metadata["days"])
    updates["default_password"] = st.text_input(
        "Default export password", type="password", value=metadata.get("default_password", "")
    )

    if st.button("Save Settings"):
        metadata.update(updates)
        save_metadata(metadata)
        st.success("Saved.")
        st.rerun()


with tabs[3]:
    st.subheader("Inspect")

    uploaded = st.file_uploader("Upload file", type=["crt", "pem", "cer", "csr", "der", "p12", "pfx"])

    password = ""
    if uploaded and uploaded.name.lower().endswith(("p12", "pfx")):
        password = st.text_input("Password", type="password")

    if uploaded:
        ctype, info = inspect_cert(uploaded.read(), password if password else None)
        st.markdown(f"Type: {ctype}")
        st.code(info)


with tabs[4]:
    st.subheader("Danger Zone")

    if "clear_ca" not in st.session_state:
        st.session_state.clear_ca = False

    if not st.session_state.clear_ca:
        if st.button("RESET ALL"):
            st.session_state.clear_ca = True
            st.rerun()

    else:
        st.warning("This deletes ALL CA data and issued certs.")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Confirm Reset"):
                _reset_ca()
                st.session_state.clear_ca = False
                st.success("CA reset.")
                st.rerun()
        with c2:
            if st.button("Cancel"):
                st.session_state.clear_ca = False
                st.rerun()

