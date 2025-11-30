import streamlit as st
from datetime import datetime
from io import BytesIO
import zipfile
import pandas as pd

from utils import (
    CA_CERT, CERTS_DIR, CA_DIR, metadata,
    create_root_ca, get_cert_expiry,
    generate_cert, sign_csr,
    export_certificate, save_metadata,
    revoke_cert, guess_mime,
    _reset_ca, safe_name,
    load_cert_metadata, inspect_cert
)

st.set_page_config(page_title="cozycerts", layout="wide")

st.markdown(
    """
    <style>
    div[data-testid="column"] button, div[data-testid="column"] .stDownloadButton button {
        padding: 0.35rem 0.75rem;
        font-size: 0.9rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

col1, col2 = st.columns([1, 4])
with col1:
    st.image("cprl.png", width=90)
with col2:
    st.title("cozycerts v3.0")

tabs = st.tabs(["Root CA", "Generate", "Metadata", "Inspect", "Reset"])


# ========================================================================
# ROOT CA
# ========================================================================
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
            expiry = get_cert_expiry(CA_CERT)
            if expiry:
                days_left = (expiry - datetime.utcnow()).days
                expiry_str = expiry.strftime("%d%b%Y@%H:%M UTC")
                if days_left < 90:
                    color = "🔴"
                elif days_left < 180:
                    color = "🟡"
                else:
                    color = "🟢"
                st.write(f"{color} rootCA → Expires {expiry_str} ({days_left} days left)")
            else:
                st.write("⚪ rootCA → Expiration unknown")

            st.download_button(
                "⬇ Download Trusted Root Certificate",
                data=CA_CERT.read_bytes(),
                file_name="rootCA.crt",
                mime="application/x-x509-ca-cert"
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
            expiry_str = "Unknown"
            days_left = "-"
            status = "⚪"

            expiry_dt = None
            if meta and meta.get("expires"):
                try:
                    expiry_dt = datetime.strptime(meta["expires"], "%Y-%m-%dT%H:%M:%SZ")
                except:
                    expiry_dt = None

            if expiry_dt:
                days_left = (expiry_dt - datetime.utcnow()).days
                expiry_str = expiry_dt.strftime("%d%b%Y @ %H:%M UTC")
            elif crt.exists():
                exp = get_cert_expiry(crt)
                if exp:
                    days_left = (exp - datetime.utcnow()).days
                    expiry_str = exp.strftime("%d%b%Y @ %H:%M UTC")

            if revoked:
                status = "⚫"
            elif not crt.exists():
                status = "⚪"
            else:
                if isinstance(days_left, int):
                    if days_left < 90:
                        status = "🔴"
                    elif days_left < 180:
                        status = "🟡"
                    else:
                        status = "🟢"

            rows.append({
                "CN": name,
                "DNS": ", ".join(meta.get("dns", [])) if meta else "",
                "IP": ", ".join(meta.get("ips", [])) if meta else "",
                "Expires": expiry_str,
                "Days Left": days_left,
                "Status": status,
                "selected": False
            })

        df = pd.DataFrame(rows)

        edited = st.data_editor(
            df,
            hide_index=True,
            column_config={
                "selected": st.column_config.CheckboxColumn("Select")
            },
            disabled=["CN", "DNS", "IP", "Expires", "Days Left", "Status"],
        )

        selected = edited[edited["selected"] == True]["CN"].tolist()

        st.markdown(
            f"###### Certificates selected: {', '.join(selected) if selected else 'None'}"
        )

        c1, c2, c3, c4 = st.columns([0.2, 0.2, 0.2, 0.2])

        with c1:
            if st.button("📦", help="Download selected as ZIP bundles") and selected:
                buf = BytesIO()
                with zipfile.ZipFile(buf, "w") as z:
                    for name in selected:
                        cert_dir = CERTS_DIR / name
                        crt = cert_dir / "cert.crt"
                        key = cert_dir / "key.pem"
                        csr = cert_dir / "req.csr"
                        if key.exists():
                            z.writestr(f"{name}/key.pem", key.read_bytes())
                        if csr.exists():
                            z.writestr(f"{name}/req.csr", csr.read_bytes())
                        if crt.exists():
                            z.writestr(f"{name}/cert.crt", crt.read_bytes())
                buf.seek(0)
                st.download_button("⬇", buf.getvalue(), file_name="certificates_bundle.zip")

        with c2:
            if st.button("🛑", help="Revoke selected certs") and selected:
                for name in selected:
                    revoke_cert(name)
                st.success("Revoked.")
                st.rerun()

        # -----------------------------------------------------------
        # EXPORT BUTTON
        # -----------------------------------------------------------
        with c3:
            fmt = st.selectbox(
                "",
                ["pem", "der", "pkcs12", "jks", "bundle"],
                label_visibility="collapsed"
            )
            password = (
                st.text_input("Password", type="password", help="Required for PKCS#12/JKS")
                if fmt in ["pkcs12", "jks"]
                else None
            )

        # -----------------------------------------------------------
        # EXPORT ACTION ICON + FORMAT DROPDOWN (emoji + colon)
        # -----------------------------------------------------------
        with c4:
            if st.button("⬇", help="Export selected certificates as:") and selected:
                out = BytesIO()
                with zipfile.ZipFile(out, "w") as z:
                    for name in selected:
                        exp_file, msg = export_certificate(name, fmt, password)
                        if exp_file:
                            z.writestr(f"{name}/{exp_file.name}", exp_file.read_bytes())
                out.seek(0)
                st.download_button("⬇ Exported", out.getvalue(), file_name="export_bundle.zip")

# ========================================================================
# CERTIFICATES
# ========================================================================
with tabs[1]:

    st.subheader("Generate New Certificate / CSR")

    cn = st.text_input("Common Name (CN)", "")

    st.markdown("Subject Alternative Names (SANs)")

    if "san_rows" not in st.session_state:
        st.session_state.san_rows = [{"type": "DNS", "value": ""}]

    drop = None
    for i, row in enumerate(st.session_state.san_rows):
        c1, c2, c3 = st.columns([2, 5, 1])
        row_type = c1.selectbox("Type", ["DNS", "IP"], index=0 if row["type"] == "DNS" else 1, key=f"san_type_{i}")
        row_value = c2.text_input("Value", row["value"], key=f"san_val_{i}")

        st.session_state.san_rows[i]["type"] = row_type
        st.session_state.san_rows[i]["value"] = row_value

        if c3.button("❌", key=f"del_{i}") and len(st.session_state.san_rows) > 1:
            drop = i

    if drop is not None:
        st.session_state.san_rows.pop(drop)
        st.rerun()

    if st.button("Add SAN Entry"):
        st.session_state.san_rows.append({"type": "DNS", "value": ""})
        st.rerun()

    dns = [r["value"].strip() for r in st.session_state.san_rows if r["type"] == "DNS" and r["value"].strip()]
    ip = [r["value"].strip() for r in st.session_state.san_rows if r["type"] == "IP" and r["value"].strip()]

    if cn and cn not in dns:
        dns = [cn] + dns

    mode = st.radio(
        "Certificate Mode",
        ["Create .crt signed by cozycerts.", "Generate CSR for other CA."],
        horizontal=True,
        index=0 if CA_CERT.exists() else 1,
    )
    self_sign = (mode == "Create .crt signed by cozycerts.")

    if st.button("Generate Cert/CSR") and cn:
        key, csr, cert = generate_cert(cn, dns, ip, self_sign)

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.write(key, arcname=key.name)
            z.write(csr, arcname=csr.name)
            if cert:
                z.write(cert, arcname=cert.name)
        buf.seek(0)

        st.success("Generated bundle.")
        st.download_button("⬇ Download", buf.getvalue(), file_name=f"{safe_name(cn)}_bundle.zip")

    st.subheader("Upload CSR to Sign")

    if not CA_CERT.exists():
        st.info("Root CA not found.")
    else:
        uploaded = st.file_uploader("CSR file", type=["csr"])
        if uploaded:
            out_name = st.text_input("Certificate name", uploaded.name.replace(".csr", ""))
            cn2 = st.text_input("CSR CN (optional)", "")
            dns_raw = st.text_input("DNS SANs (comma-separated)", "")
            ip_raw = st.text_input("IP SANs (comma-separated)", "")

            dns2 = [x.strip() for x in dns_raw.split(",") if x.strip()]
            ip2 = [x.strip() for x in ip_raw.split(",") if x.strip()]

            if st.button("Sign CSR"):
                base = safe_name(out_name)
                cert_dir = CERTS_DIR / base
                cert_dir.mkdir(exist_ok=True)

                csr_path = cert_dir / "req.csr"
                csr_path.write_bytes(uploaded.read())

                cert_file = sign_csr(csr_path, base, dns2, ip2, cn=cn2 or None)

                st.success("Certificate issued.")
                st.download_button("⬇ Download Certificate", cert_file.read_bytes(), cert_file.name)


# ========================================================================
# METADATA
# ========================================================================
with tabs[2]:
    st.subheader("Metadata Defaults")

    country = st.text_input("Country", metadata["country"])
    state = st.text_input("State", metadata["state"])
    locality = st.text_input("Locality", metadata["locality"])
    org = st.text_input("Organization", metadata["org"])
    ou = st.text_input("Organizational Unit", metadata["ou"])
    days = st.number_input("Validity (days)", min_value=1, value=metadata["days"])
    default_password = st.text_input("Default export password", type="password", value=metadata.get("default_password", ""))

    if st.button("Save Settings"):
        metadata.update({
            "country": country,
            "state": state,
            "locality": locality,
            "org": org,
            "ou": ou,
            "days": days,
            "default_password": default_password
        })
        save_metadata(metadata)
        st.success("Saved.")
        st.rerun()


# ========================================================================
# INSPECTOR
# ========================================================================
with tabs[3]:
    st.subheader("Inspect Certificate / CSR / PKCS#12")

    uploaded = st.file_uploader("Upload file", type=["crt", "pem", "cer", "csr", "der", "p12", "pfx"])

    password = ""
    if uploaded and uploaded.name.lower().endswith(("p12", "pfx")):
        password = st.text_input("Password", type="password")

    if uploaded:
        ctype, info = inspect_cert(uploaded.read(), password if password else None)
        st.markdown(f"Type: {ctype}")
        st.code(info)


# ========================================================================
# DANGER ZONE
# ========================================================================
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

