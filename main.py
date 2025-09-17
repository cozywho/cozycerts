import streamlit as st
import subprocess
import yaml
from pathlib import Path
from datetime import datetime

# --- Config ---
CONFIG_FILE = "config.yaml"
if Path(CONFIG_FILE).exists():
    with open(CONFIG_FILE) as f:
        config = yaml.safe_load(f)
else:
    config = {"base_dir": "./certs", "ca_dir": "./ca", "default_days": 365}

BASE_DIR = Path(config["base_dir"])
CA_DIR = Path(config["ca_dir"])
CERTS_DIR = BASE_DIR / "issued"

# Ensure directories exist
BASE_DIR.mkdir(parents=True, exist_ok=True)
CA_DIR.mkdir(parents=True, exist_ok=True)
CERTS_DIR.mkdir(parents=True, exist_ok=True)

# CA files
CA_KEY = CA_DIR / "rootCA.key"
CA_CERT = CA_DIR / "rootCA.crt"

# Ansible files
ANSIBLE_INVENTORY = Path("ansible/inventories/lab_hosts.yml")
ANSIBLE_PLAYBOOK = Path("ansible/playbooks/issue-cert.yml")

# --- Helper functions ---
def create_root_ca():
    """Create a Root CA key + self-signed certificate."""
    try:
        subprocess.run(
            ["openssl", "genrsa", "-out", str(CA_KEY), "4096"], check=True
        )
        subprocess.run(
            [
                "openssl", "req", "-x509", "-new", "-nodes",
                "-key", str(CA_KEY),
                "-sha256", "-days", str(config["default_days"]),
                "-subj", "/C=US/ST=NC/L=CozyLab/O=CozyCerts/OU=CA/CN=CozyCerts-RootCA",
                "-out", str(CA_CERT),
            ],
            check=True
        )
        return True, "Root CA created successfully."
    except subprocess.CalledProcessError as e:
        return False, f"Error creating Root CA: {e}"

def get_ca_expiry():
    """Return expiry datetime of Root CA, or None if not present."""
    if not CA_CERT.exists():
        return None
    try:
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", str(CA_CERT)],
            capture_output=True, text=True, check=True
        )
        out = result.stdout.strip()
        date_str = out.split("=", 1)[1].strip()  # "notAfter=Sep 17 12:34:56 2027 GMT"
        expiry_dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
        return expiry_dt
    except subprocess.CalledProcessError:
        return None

def load_hosts():
    """Parse Ansible inventory YAML and return hostnames."""
    if not ANSIBLE_INVENTORY.exists():
        return []
    with open(ANSIBLE_INVENTORY) as f:
        data = yaml.safe_load(f)
    return list(data.get("all", {}).get("hosts", {}).keys())

def run_ansible_playbook(host):
    """Execute Ansible playbook for a single host."""
    cmd = [
        "ansible-playbook",
        str(ANSIBLE_PLAYBOOK),
        "-i", str(ANSIBLE_INVENTORY),
        "--limit", host
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode

# --- Streamlit UI ---
st.set_page_config(page_title="CozyCerts Manager", layout="wide")
st.title("🔐 CozyCerts - Certificate Authority")

tabs = st.tabs(["CA Status", "Certificates", "Hosts", "Actions"])

# --- Tab 1: CA Status ---
with tabs[0]:
    st.subheader("Root CA Status")
    if CA_CERT.exists():
        st.success(f"Root CA exists: {CA_CERT}")
        expiry = get_ca_expiry()
        if expiry:
            days_left = (expiry - datetime.utcnow()).days
            st.write(f"**Expires on:** {expiry} UTC")
            st.write(f"**Days remaining:** {days_left} days" if days_left >= 0 else f"***Expired {-days_left} days ago***")
        st.code(CA_CERT.read_text()[:200] + "...\n", language="text")
    else:
        st.error("No Root CA found")
        if st.button("Create Root CA"):
            ok, msg = create_root_ca()
            if ok:
                st.success(msg)
            else:
                st.error(msg)

# --- Tab 2: Certificates ---
with tabs[1]:
    st.subheader("Issued Certificates")
    cert_files = list(CERTS_DIR.glob("*.crt"))
    if cert_files:
        for cert in cert_files:
            st.write(f"📜 {cert.name}")
            # Optional: parse expiration using openssl x509 -enddate
    else:
        st.warning("No certificates issued yet")

# --- Tab 3: Hosts ---
with tabs[2]:
    st.subheader("Hosts Inventory")
    hosts = load_hosts()
    if not hosts:
        st.warning("No hosts defined in Ansible inventory.")
    else:
        st.write("Hosts available in inventory:")
        for h in hosts:
            st.write(f"- {h}")

# --- Tab 4: Actions ---
with tabs[3]:
    st.subheader("Certificate Actions")
    hosts = load_hosts()
    if hosts:
        selected_host = st.selectbox("Select host", hosts)
        if st.button("Issue / Renew Certificate"):
            st.info(f"Running Ansible cert workflow for **{selected_host}** ...")
            stdout, stderr, rc = run_ansible_playbook(selected_host)
            if rc == 0:
                st.success("✅ Certificate issued and deployed successfully!")
            else:
                st.error("❌ Playbook failed")
                st.code(stderr, language="bash")
            st.subheader("Ansible output")
            st.code(stdout, language="bash")
    else:
        st.warning("No hosts available to issue certificates.")
