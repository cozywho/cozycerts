import streamlit as st
from datetime import datetime
from io import BytesIO
import zipfile
import shutil

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

# ---------- header ----------
col1, col2 = st.columns([1, 4])
with col1:
    st.image("cprl.png", width=90)
with col2:
    st.title("cozycerts v3.0")

tabs = st.tabs(["Root CA", "Certificates", "Metadata", "Inspect"])


# ============================================================
# --- Tab 1: Root CA / Dashboard ---
# ============================================================
with tabs[0]:
    st.subheader("Root CA")

    if not CA_CERT.exists():
        st.error("No Root CA found. Please create one.")
        if st.button("Create Root CA"):
            create_root_ca()
            st.success("Root CA created")
            st.rerun()
    else:
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
            st.write(f"{color} **rootCA** → Expires {expiry_str} ({days_left} days left)")
        else:
            st.write("⚪ **rootCA** → Expiration unknown")

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

    # --- Certificate Dashboard ---
    st.subheader("Certificate Dashboard")

    issued_dirs = [d for d in CERTS_DIR.iterdir() if d.is_dir()]
    if not issued_dirs:
        st.info("No certificate entries yet (CSRs or signed certs).")
    else:
        for cert_dir in issued_dirs:
            name = cert_dir.name
            crt = cert_dir / "cert.crt"
            key = cert_dir / "key.pem"
            csr = cert_dir / "req.csr"

            meta = load_cert_metadata(cert_dir)
            cn = meta.get("cn", name) if meta else name
            revoked = bool(meta.get("revoked", False)) if meta else False

            expiry_str = "Unknown"
            days_left = "-"
            expiry_dt = None

            if meta and meta.get("expires"):
                try:
                    expiry_dt = datetime.strptime(meta["expires"], "%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    expiry_dt = None

            if expiry_dt:
                days_left = (expiry_dt - datetime.utcnow()).days
                expiry_str = expiry_dt.strftime("%d%b%Y @ %H:%M UTC")
            elif crt.exists():
                # fallback to OpenSSL if metadata missing
                exp = get_cert_expiry(crt)
                if exp:
                    days_left = (exp - datetime.utcnow()).days
                    expiry_str = exp.strftime("%d%b%Y @ %H:%M UTC")

            # status
            if revoked:
                status_icon = "⚫"
            elif not crt.exists():
                status_icon = "⚪"  # CSR only
            else:
                if isinstance(days_left, int):
                    if days_left < 90:
                        status_icon = "🔴"
                    elif days_left < 180:
                        status_icon = "🟡"
                    else:
                        status_icon = "🟢"
                else:
                    status_icon = "⚪"

            row = st.container()
            cols = row.columns([2, 3, 2, 2, 3])

            cols[0].markdown(f"**{name}**\n`CN: {cn}`")
            cols[1].write(expiry_str)
            cols[2].write(days_left)
            cols[3].write(status_icon)

            with cols[4]:
                if st.button("Download", key=f"dl-{name}"):
                    buf = BytesIO()
                    with zipfile.ZipFile(buf, "w") as z:
                        if key.exists():
                            z.writestr("key.pem", key.read_bytes())
                        if csr.exists():
                            z.writestr("req.csr", csr.read_bytes())
                        if crt.exists():
                            z.writestr("cert.crt", crt.read_bytes())
                    buf.seek(0)
                    st.download_button(
                        f"⬇ {name}.zip",
                        buf.getvalue(),
                        file_name=f"{name}.zip",
                        key=f"dlbtn-{name}"
                    )

                if crt.exists():
                    fmt = st.selectbox(
                        f"Export format for {name}",
                        ["pem", "der", "pkcs12", "jks", "bundle"],
                        key=f"fmt-{name}"
                    )
                    password = None
                    if fmt in ["pkcs12", "jks"]:
                        password = st.text_input(
                            f"Password for {name}",
                            type="password",
                            key=f"pw-{name}"
                        )
                    if st.button("Export", key=f"export-{name}"):
                        out_file, msg = export_certificate(name, fmt, password)
                        if out_file:
                            mime = guess_mime(out_file.name)
                            st.download_button(
                                f"⬇ {out_file.name}",
                                out_file.read_bytes(),
                                out_file.name,
                                mime=mime,
                                key=f"outfile-{name}"
                            )
                        else:
                            st.error(msg)

                if st.button("Revoke", key=f"revoke-{name}"):
                    ok, msg = revoke_cert(name)
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

    crl_file = CA_DIR / "crl.pem"
    if crl_file.exists():
        st.download_button("⬇ Download CRL", crl_file.read_bytes(), "crl.pem")

    # --- Danger Zone ---
    st.divider()
    st.subheader("Danger Zone")

    if "clear_ca_confirm" not in st.session_state:
        st.session_state.clear_ca_confirm = False

    if not st.session_state.clear_ca_confirm:
        if st.button("RESET ALL"):
            st.session_state.clear_ca_confirm = True
            st.rerun()
    else:
        st.warning(
            "Warning: Resetting to factory settings. "
            "This will delete ALL CA data and issued certs (keeps only openssl.cnf)."
        )
        c1, c2 = st.columns(2)
        with c1:
            if st.button("✅ Yes, reset now"):
                _reset_ca()
                st.session_state.clear_ca_confirm = False
                st.success("CA has been reset to factory settings. Create a new Root CA.")
                st.rerun()
        with c2:
            if st.button("Cancel"):
                st.session_state.clear_ca_confirm = False
                st.info("Cancelled.")
                st.rerun()


# ============================================================
# --- Tab 2: Certificates (generation + signing) ---
# ============================================================
with tabs[1]:

    st.subheader("Generate New Certificate / CSR")

    # --- CN input ---
    cn = st.text_input("Common Name (CN)", "")

    # --- SAN builder ---
    st.markdown("**Subject Alternative Names (SAN)**")

    if "san_rows" not in st.session_state:
        st.session_state.san_rows = [{"type": "DNS", "value": ""}]

    delete_index = None
    for i, row in enumerate(st.session_state.san_rows):
        c1, c2, c3 = st.columns([2, 4, 1])
        row_type = c1.selectbox(
            "Type",
            ["DNS", "IP"],
            index=0 if row["type"] == "DNS" else 1,
            key=f"san_type_{i}"
        )
        row_value = c2.text_input("Value", row["value"], key=f"san_val_{i}")
        st.session_state.san_rows[i]["type"] = row_type
        st.session_state.san_rows[i]["value"] = row_value

        if c3.button("❌", key=f"san_del_{i}") and len(st.session_state.san_rows) > 1:
            delete_index = i

    if delete_index is not None:
        st.session_state.san_rows.pop(delete_index)
        st.rerun()

    if st.button("Add SAN Entry"):
        st.session_state.san_rows.append({"type": "DNS", "value": ""})
        st.rerun()

    # derive lists
    dns_list = [
        r["value"].strip() for r in st.session_state.san_rows
        if r["type"] == "DNS" and r["value"].strip()
    ]
    ip_list = [
        r["value"].strip() for r in st.session_state.san_rows
        if r["type"] == "IP" and r["value"].strip()
    ]

    # ensure CN is at least represented in DNS list if not present
    if cn and cn not in dns_list:
        dns_list = [cn] + dns_list

    # --- Mode selector ---
    mode = st.radio(
        "Certificate Mode",
        [
            "Create .crt signed by cozycerts.",
            "Generate CSR for other certificate authority."
        ],
        horizontal=True,
        index=0 if CA_CERT.exists() else 1,
        key="cert_mode_selector"
    )
    self_sign = (mode == "Create .crt signed by cozycerts.")

    # --- Generate button ---
    if st.button("Generate Cert/CSR") and cn:
        key_file, csr_file, cert_file = generate_cert(cn, dns_list, ip_list, self_sign)

        if self_sign and cert_file:
            st.success(f"Generated {key_file.name}, {csr_file.name}, {cert_file.name}")
        else:
            st.success(f"Generated {key_file.name}, {csr_file.name} (unsigned CSR only)")

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.write(key_file, arcname=key_file.name)
            z.write(csr_file, arcname=csr_file.name)
            if self_sign and cert_file:
                z.write(cert_file, arcname=cert_file.name)
        buf.seek(0)

        st.download_button(
            "⬇ Download Key / CSR / Cert",
            buf,
            file_name=f"{safe_name(cn)}_bundle.zip",
            key=f"generated-{cn}"
        )

    st.subheader("Upload CSR to Sign")

    if not CA_CERT.exists():
        st.info("Root CA not found — CSR signing disabled until a Root CA is created.")
    else:
        uploaded_csr = st.file_uploader("Choose CSR file", type=["csr"])
        if uploaded_csr:
            out_name = st.text_input(
                "Certificate name (folder/short name)",
                uploaded_csr.name.replace(".csr", "")
            )
            cn_for_csr = st.text_input("Common Name (CN) for CSR (optional)", "")
            dns_for_csr_raw = st.text_input("DNS SANs (comma-separated)", "")
            ip_for_csr_raw = st.text_input("IP SANs (comma-separated)", "")

            dns_for_csr = [
                x.strip() for x in dns_for_csr_raw.split(",") if x.strip()
            ]
            ip_for_csr = [
                x.strip() for x in ip_for_csr_raw.split(",") if x.strip()
            ]

            if st.button("Sign CSR"):
                base = safe_name(out_name)
                cert_dir = CERTS_DIR / base
                cert_dir.mkdir(exist_ok=True)

                csr_path = cert_dir / "req.csr"
                csr_path.write_bytes(uploaded_csr.read())

                cert_file = sign_csr(csr_path, base, dns_for_csr, ip_for_csr, cn=cn_for_csr or None)

                st.success(f"Issued certificate: {cert_file.name}")
                st.download_button(
                    "⬇ Download Certificate",
                    cert_file.read_bytes(),
                    cert_file.name,
                    key=f"signed-{base}"
                )


# ============================================================
# --- Tab 3: Settings / Root metadata ---
# ============================================================
with tabs[2]:
    st.subheader("Certificate Metadata Defaults")

    country = st.text_input("Country", metadata["country"])
    state = st.text_input("State", metadata["state"])
    locality = st.text_input("Locality", metadata["locality"])
    org = st.text_input("Organization", metadata["org"])
    ou = st.text_input("Organizational Unit", metadata["ou"])
    days = st.number_input("Validity (days)", min_value=1, value=metadata["days"])
    default_password = st.text_input(
        "Default password for exports (optional)",
        type="password",
        value=metadata.get("default_password", "")
    )

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
        st.success("Settings saved")
        st.rerun()


# ============================================================
# --- Tab 4: Inspect ---
# ============================================================
with tabs[3]:
    st.subheader("Inspect Certificate / CSR / PKCS#12")

    uploaded = st.file_uploader(
        "Upload certificate / CSR / PKCS#12 / PFX",
        type=["crt", "pem", "cer", "csr", "der", "p12", "pfx"]
    )

    password = ""
    if uploaded and uploaded.name.lower().endswith(("p12", "pfx")):
        password = st.text_input("Password (for PKCS#12 / PFX)", type="password")

    if uploaded:
        ctype, info = inspect_cert(uploaded.read(), password if password else None)
        st.markdown(f"**Detected Type:** {ctype}")
        st.code(info)
