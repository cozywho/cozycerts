import streamlit as st
import subprocess
from pathlib import Path
from datetime import datetime
import yaml
import zipfile

# --- Directories ---
BASE_DIR = Path(".")
CA_DIR = BASE_DIR / "ca"
CERTS_DIR = BASE_DIR / "certs"
EXPORT_DIR = BASE_DIR / "exports"

for d in [CA_DIR, CERTS_DIR, EXPORT_DIR]:
    d.mkdir(exist_ok=True)

CA_KEY = CA_DIR / "rootCA.key"
CA_CERT = CA_DIR / "rootCA.crt"
META_FILE = BASE_DIR / "metadata.yaml"

# --- Default Metadata ---
default_meta = {
    "country": "US",
    "state": "NC",
    "locality": "Lab",
    "org": "CozyCerts",
    "ou": "General",
    "days": 365,
    "default_password": ""
}

# Load metadata
if META_FILE.exists():
    with open(META_FILE) as f:
        metadata = yaml.safe_load(f)
else:
    metadata = default_meta.copy()

# --- Helpers ---
def save_metadata(data):
    with open(META_FILE, "w") as f:
        yaml.safe_dump(data, f)

def create_root_ca():
    subprocess.run(["openssl", "genrsa", "-out", str(CA_KEY), "4096"], check=True)
    subj = f"/C={metadata['country']}/ST={metadata['state']}/L={metadata['locality']}/O={metadata['org']}/OU=CA/CN=CozyRoot"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-new", "-nodes",
            "-key", str(CA_KEY),
            "-sha256", "-days", str(metadata['days']),
            "-subj", subj,
            "-out", str(CA_CERT),
        ],
        check=True
    )

def sign_csr(csr_file: Path, out_name: str):
    cert_file = CERTS_DIR / f"{out_name}.crt"
    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", str(csr_file),
            "-CA", str(CA_CERT), "-CAkey", str(CA_KEY),
            "-CAcreateserial",
            "-out", str(cert_file), "-days", str(metadata['days']), "-sha256",
        ],
        check=True
    )
    return cert_file

def generate_cert(name: str):
    key_file = CERTS_DIR / f"{name}.key"
    csr_file = CERTS_DIR / f"{name}.csr"
    cert_file = CERTS_DIR / f"{name}.crt"

    subj = f"/C={metadata['country']}/ST={metadata['state']}/L={metadata['locality']}/O={metadata['org']}/OU={metadata['ou']}/CN={name}"

    subprocess.run(["openssl", "genrsa", "-out", str(key_file), "2048"], check=True)
    subprocess.run(
        ["openssl", "req", "-new", "-key", str(key_file), "-subj", subj, "-out", str(csr_file)],
        check=True
    )
    sign_csr(csr_file, name)
    return key_file, csr_file, cert_file

def get_cert_expiry(cert_file: Path):
    try:
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", str(cert_file)],
            capture_output=True, text=True, check=True
        )
        date_str = result.stdout.strip().split("=", 1)[1].strip()
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
    except Exception:
        return None

def export_certificate(name: str, fmt: str, password: str = None):
    crt = CERTS_DIR / f"{name}.crt"
    key = CERTS_DIR / f"{name}.key"
    out_file = EXPORT_DIR / f"{name}.{fmt.lower()}"

    if not crt.exists():
        return None, "Missing certificate file"

    try:
        if fmt.upper() == "PEM":
            # Combine cert, key, and root (if available)
            parts = []
            if key.exists():
                parts.append(key.read_text())
            parts.append(crt.read_text())
            if CA_CERT.exists():
                parts.append(CA_CERT.read_text())
            out_file.write_text("\n".join(parts))

        elif fmt.upper() == "DER":
            subprocess.run(
                ["openssl", "x509", "-in", str(crt), "-outform", "der", "-out", str(out_file)],
                check=True
            )

        elif fmt.upper() == "PKCS12":
            password = password or metadata["default_password"]
            if not password:
                return None, "Password required for PKCS#12 export"
            subprocess.run(
                ["openssl", "pkcs12", "-export",
                 "-inkey", str(key), "-in", str(crt),
                 "-certfile", str(CA_CERT), "-out", str(out_file),
                 "-password", f"pass:{password}"],
                check=True
            )

        elif fmt.upper() == "JKS":
            password = password or metadata["default_password"]
            if not password:
                return None, "Password required for JKS export"
            p12_file = EXPORT_DIR / f"{name}.p12"
            subprocess.run(
                ["openssl", "pkcs12", "-export",
                 "-inkey", str(key), "-in", str(crt),
                 "-certfile", str(CA_CERT), "-out", str(p12_file),
                 "-password", f"pass:{password}"],
                check=True
            )
            subprocess.run(
                ["keytool", "-importkeystore",
                 "-srckeystore", str(p12_file), "-srcstoretype", "PKCS12", "-srcstorepass", password,
                 "-destkeystore", str(out_file), "-deststoretype", "JKS", "-deststorepass", password],
                check=True
            )

        elif fmt.upper() == "BUNDLE":
            # Create a PEM fullchain
            fullchain_file = EXPORT_DIR / f"{name}_fullchain.pem"
            parts = [crt.read_text()]
            if CA_CERT.exists():
                parts.append(CA_CERT.read_text())
            fullchain_file.write_text("\n".join(parts))

            # Also create a ZIP archive with everything
            zip_file = EXPORT_DIR / f"{name}_bundle.zip"
            with zipfile.ZipFile(zip_file, "w") as zf:
                zf.write(crt, arcname=f"{name}.crt")
                if key.exists():
                    zf.write(key, arcname=f"{name}.key")
                if CA_CERT.exists():
                    zf.write(CA_CERT, arcname="rootCA.crt")
                zf.write(fullchain_file, arcname=f"{name}_fullchain.pem")

            out_file = zip_file  # default download will be ZIP

        else:
            return None, f"Unsupported format: {fmt}"

        return out_file, f"Exported {name} as {fmt}"
    except subprocess.CalledProcessError as e:
        return None, f"Error exporting: {e}"

# --- Streamlit UI ---
st.set_page_config(page_title="cozycerts", layout="wide")

# Logo + Title
col1, col2 = st.columns([1,4])
with col1:
    st.image("cprl.png", width=90)
with col2:
    st.title("cozycerts")

tabs = st.tabs(["Certificates", "Settings"])

# --- Tab 1: Certificates ---
with tabs[0]:
    # Root CA
    st.header("Root CA")
    if not CA_CERT.exists():
        st.error("No Root CA found. Please create one.")
        if st.button("Create Root CA"):
            create_root_ca()
            st.success("Root CA created")
    else:
        expiry = get_cert_expiry(CA_CERT)
        if expiry:
            days_left = (expiry - datetime.utcnow()).days
            st.write(f"**Expiration:** {expiry} UTC")
            st.write(f"**Days left:** {days_left}")
        st.download_button("⬇ Download Trusted Root Certificate", CA_CERT.read_bytes(), "rootCA.crt")
        st.info("""
        **Fedora / Rocky / RHEL**
        ```bash
        sudo cp rootCA.crt /etc/pki/ca-trust/source/anchors/
        sudo update-ca-trust extract
        ```
    
        **Debian / Ubuntu**
        ```bash
        sudo cp rootCA.crt /usr/local/share/ca-certificates/
        sudo update-ca-certificates
        ```
        """)

    # Upload CSR
    st.header("Upload CSR to Sign")
    uploaded_csr = st.file_uploader("Choose CSR file", type=["csr"])
    if uploaded_csr and CA_CERT.exists():
        out_name = st.text_input("Certificate name (no extension)", uploaded_csr.name.replace(".csr", ""))
        if st.button("Sign CSR"):
            csr_path = CERTS_DIR / uploaded_csr.name
            csr_path.write_bytes(uploaded_csr.read())
            cert_file = sign_csr(csr_path, out_name)
            st.success(f"Issued certificate: {cert_file.name}")
            st.download_button("⬇ Download Certificate", cert_file.read_bytes(), cert_file.name)

    # Generate cert
    st.header("Generate New Certificate")
    new_name = st.text_input("Common Name (CN)", "")
    if st.button("Generate Cert") and new_name:
        key_file, csr_file, cert_file = generate_cert(new_name)
        st.success(f"Generated {key_file.name}, {csr_file.name}, {cert_file.name}")

    # Inventory
    st.header("Inventory")
    issued = [crt.stem for crt in CERTS_DIR.glob("*.crt")]
    if not issued:
        st.warning("No certificates have been issued yet.")
    else:
        for name in issued:
            crt = CERTS_DIR / f"{name}.crt"
            key = CERTS_DIR / f"{name}.key"
            csr = CERTS_DIR / f"{name}.csr"
    
            # Expiry info
            expiry = get_cert_expiry(crt)
            if expiry:
                days_left = (expiry - datetime.utcnow()).days
                st.write(f"**{name}** → Expires {expiry} UTC ({days_left} days left)")
            else:
                st.write(f"**{name}** → Expiration unknown")
    
            # Direct downloads
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                if key.exists():
                    st.download_button("⬇ Key", key.read_bytes(), key.name, key=f"key-{name}")
            with col2:
                if csr.exists():
                    st.download_button("⬇ CSR", csr.read_bytes(), csr.name, key=f"csr-{name}")
            with col3:
                st.download_button("⬇ Cert", crt.read_bytes(), crt.name, key=f"crt-{name}")
            with col4: 
                # Export options
                fmt = st.selectbox(
                    f"Export as:", 
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

# --- Tab 2: Settings ---
with tabs[1]:
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

