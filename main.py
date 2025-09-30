import streamlit as st
from datetime import datetime
from io import BytesIO
import zipfile
import shutil
from utils import (
    CA_CERT, CERTS_DIR, metadata,
    create_root_ca, get_cert_expiry, sign_csr,
    generate_cert, export_certificate,
    save_metadata, revoke_cert, CA_DIR
)

st.set_page_config(page_title="cozycerts", layout="wide")

# ---------- helpers ----------
def _reset_ca():
    # wipe everything under ca/ except openssl.cnf
    for f in CA_DIR.glob("*"):
        if f.name == "openssl.cnf":
            continue
        if f.is_file():
            f.unlink()
        elif f.is_dir():
            shutil.rmtree(f)

    # required OpenSSL bookkeeping
    (CA_DIR / "index.txt").write_text("")           # DB
    (CA_DIR / "serial").write_text("1000\n")        # first serial
    (CA_DIR / "crlnumber").write_text("1000\n")     # first CRL number

    # ensure newcerts exists
    (CA_DIR / "newcerts").mkdir(parents=True, exist_ok=True)

    # clear issued certs/keys/csrs
    if CERTS_DIR.exists():
        shutil.rmtree(CERTS_DIR)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    # remove old CRL if present
    crl_file = CA_DIR / "crl.pem"
    if crl_file.exists():
        crl_file.unlink()

# ---------- header ----------
col1, col2 = st.columns([1, 4])
with col1:
    st.image("cprl.png", width=90)
with col2:
    st.title("cozycerts")

tabs = st.tabs(["Root CA", "Certificates", "Settings"])

# --- Tab 1: Root CA ---
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

        st.download_button("⬇ Download Trusted Root Certificate", CA_CERT.read_bytes(), "rootCA.crt")

        with st.expander("Install Instructions"):
            st.markdown("""
            **Fedora / Rocky / RHEL**
            ```bash
            sudo cp rootCA.crt /etc/pki/ca-trust/source/anchors/
            sudo update-ca-trust extract
            ```
            """)

    st.subheader("Inventory")
    issued = [crt.stem for crt in CERTS_DIR.glob("*.crt")]
    if not issued:
        st.warning("No certificates have been issued yet.")
    else:
        for name in issued:
            crt = CERTS_DIR / f"{name}.crt"
            key = CERTS_DIR / f"{name}.key"
            csr = CERTS_DIR / f"{name}.csr"
            expiry = get_cert_expiry(crt)

            if expiry:
                days_left = (expiry - datetime.utcnow()).days
                expiry_str = expiry.strftime("%d%b%Y@%H:%M UTC")
                if days_left < 90:
                    color = "🔴"
                elif days_left < 180:
                    color = "🟡"
                else:
                    color = "🟢"
                header_text = f"{color} **{name}** → Expires {expiry_str} ({days_left} days left)"
            else:
                header_text = f"⚪ **{name}** → Expiration unknown"

            with st.expander(header_text, expanded=False):
                dl_key = st.checkbox("Key", key=f"chk-key-{name}")
                dl_csr = st.checkbox("CSR", key=f"chk-csr-{name}")
                dl_crt = st.checkbox("Cert", key=f"chk-crt-{name}")

                if st.button("⬇ Download Selected", key=f"dl-selected-{name}"):
                    buf = BytesIO()
                    with zipfile.ZipFile(buf, "w") as z:
                        if dl_key and key.exists():
                            z.writestr(key.name, key.read_bytes())
                        if dl_csr and csr.exists():
                            z.writestr(csr.name, csr.read_bytes())
                        if dl_crt and crt.exists():
                            z.writestr(crt.name, crt.read_bytes())
                    buf.seek(0)

                    st.download_button(
                        "⬇ Download Bundle",
                        buf,
                        file_name=f"{name}_selected.zip",
                        key=f"bundle-{name}"
                    )

                fmt = st.selectbox(
                    f"Export format for {name}:",
                    ["pem", "der", "pkcs12", "jks", "bundle"],
                    key=f"fmt-{name}"
                )
                password = None
                if fmt in ["pkcs12", "jks"]:
                    password = st.text_input(f"Password for {name}", type="password", key=f"pw-{name}")
                if st.button(f"Export {name}", key=f"dl-{name}"):
                    out_file, msg = export_certificate(name, fmt, password)
                    if out_file:
                        st.download_button(
                            f"⬇ Download {out_file.name}",
                            out_file.read_bytes(),
                            out_file.name,
                            key=f"btn-{name}"
                        )
                    else:
                        st.error(msg)

                if st.button("❌ Revoke", key=f"revoke-{name}"):
                    ok, msg = revoke_cert(name)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)

    crl_file = CA_DIR / "crl.pem"
    if crl_file.exists():
        st.download_button("⬇ Download CRL", crl_file.read_bytes(), "crl.pem")

    # --- Danger Zone (two-step confirm with session state) ---
    st.divider()
    st.subheader("Danger Zone")

    if "clear_ca_confirm" not in st.session_state:
        st.session_state.clear_ca_confirm = False

    if not st.session_state.clear_ca_confirm:
        if st.button("RESET ALL"):
            st.session_state.clear_ca_confirm = True
            st.rerun()
    else:
        st.warning("Warning: Resetting to factory settings. This will delete ALL CA data and issued certs (keeps only openssl.cnf).")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("✅ Yes, reset now"):
                _reset_ca()
                st.session_state.clear_ca_confirm = False
                st.success("CA has been reset to factory settings. Create a new Root CA before issuing certs.")
                st.rerun()
        with c2:
            if st.button("Cancel"):
                st.session_state.clear_ca_confirm = False
                st.info("Cancelled.")
                st.rerun()

# --- Tab 2: Certificates ---
with tabs[1]:
    st.subheader("Upload CSR to Sign")
    uploaded_csr = st.file_uploader("Choose CSR file", type=["csr"])
    if uploaded_csr and CA_CERT.exists():
        out_name = st.text_input("Certificate name (no extension)", uploaded_csr.name.replace(".csr", ""))
        dns_for_csr = st.text_input("DNS for CSR", "")
        ip_for_csr = st.text_input("IP for CSR", "")
        if st.button("Sign CSR") and dns_for_csr:
            csr_path = CERTS_DIR / uploaded_csr.name
            csr_path.write_bytes(uploaded_csr.read())
            cert_file = sign_csr(csr_path, out_name, dns_for_csr, ip_for_csr)
            st.success(f"Issued certificate: {cert_file.name}")
            st.download_button("⬇ Download Certificate", cert_file.read_bytes(), cert_file.name)

    st.subheader("Generate New Certificate")
    dns_name = st.text_input("DNS Name (e.g. service.domain.lan)", "")
    ip_addr = st.text_input("IP Address (e.g. 10.x.x.x)", "")
    self_sign = st.toggle("Self-sign with Root CA", value=True)

    if st.button("Generate Cert/CSR") and dns_name:
        key_file, csr_file, cert_file = generate_cert(dns_name, ip_addr, self_sign)
        if self_sign and cert_file:
            st.success(f"Generated {key_file.name}, {csr_file.name}, {cert_file.name}")
        else:
            st.success(f"Generated {key_file.name}, {csr_file.name} (unsigned CSR only)")

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.write(key_file, arcname=key_file.name)
            z.write(csr_file, arcname=csr_file.name)
        buf.seek(0)

        st.download_button(
            "⬇ Download CSR + Key",
            buf,
            file_name=f"{dns_name}_unsigned.zip",
            key=f"unsigned-{dns_name}"
        )

# --- Tab 3: Settings ---
with tabs[2]:
    st.subheader("Certificate Metadata")
    country = st.text_input("Country", metadata["country"])
    state = st.text_input("State", metadata["state"])
    locality = st.text_input("Locality", metadata["locality"])
    org = st.text_input("Organization", metadata["org"])
    ou = st.text_input("Organizational Unit", metadata["ou"])
    days = st.number_input("Validity (days)", min_value=1, value=metadata["days"])
    default_password = st.text_input("Default password", type="password", value=metadata.get("default_password", ""))

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
