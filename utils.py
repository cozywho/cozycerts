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
OPENSSL_CNF = CA_DIR / "openssl.cnf"

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
    # init DB if not present
    (CA_DIR / "index.txt").touch(exist_ok=True)
    if not (CA_DIR / "serial").exists():
        (CA_DIR / "serial").write_text("1000\n")
    if not (CA_DIR / "crlnumber").exists():
        (CA_DIR / "crlnumber").write_text("1000\n")

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

def sign_csr(csr_file: Path, out_name: str, dns_name: str, ip_addr: str):
    cert_file = CERTS_DIR / f"{out_name}.crt"
    ext_file = CERTS_DIR / f"{out_name}_ext.cnf"

    san_entries = []
    if dns_name:
        san_entries.append(f"DNS:{dns_name}")
    if ip_addr:
        san_entries.append(f"IP:{ip_addr}")

    with open(ext_file, "w") as f:
        f.write("[ v3_req ]\n")
        f.write("subjectAltName=" + ",".join(san_entries) + "\n")

    subprocess.run(
        [
            "openssl", "ca",
            "-config", str(OPENSSL_CNF),
            "-extensions", "v3_req",
            "-extfile", str(ext_file),
            "-in", str(csr_file),
            "-out", str(cert_file),
            "-batch"
        ],
        check=True
    )
    return cert_file

def generate_cert(dns_name: str, ip_addr: str, self_sign: bool = True):
    key_file = CERTS_DIR / f"{dns_name}.key"
    csr_file = CERTS_DIR / f"{dns_name}.csr"
    cert_file = CERTS_DIR / f"{dns_name}.crt"

    subj = f"/C={metadata['country']}/ST={metadata['state']}/L={metadata['locality']}/O={metadata['org']}/OU={metadata['ou']}/CN={dns_name}"

    san_entries = []
    if dns_name:
        san_entries.append(f"DNS:{dns_name}")
    if ip_addr:
        san_entries.append(f"IP:{ip_addr}")
    san_str = ",".join(san_entries)

    subprocess.run(["openssl", "genrsa", "-out", str(key_file), "2048"], check=True)

    csr_cmd = [
        "openssl", "req", "-new",
        "-key", str(key_file),
        "-subj", subj,
        "-out", str(csr_file)
    ]
    if san_entries:
        csr_cmd.extend(["-addext", f"subjectAltName={san_str}"])

    subprocess.run(csr_cmd, check=True)

    # If self-sign requested, sign with CozyCerts RootCA
    if self_sign:
        sign_csr(csr_file, dns_name, dns_name, ip_addr)
        return key_file, csr_file, cert_file
    else:
        # Return only key + CSR; SANs are already in CSR
        return key_file, csr_file, None


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
            fullchain_file = EXPORT_DIR / f"{name}_fullchain.pem"
            parts = [crt.read_text()]
            if CA_CERT.exists():
                parts.append(CA_CERT.read_text())
            fullchain_file.write_text("\n".join(parts))

            zip_file = EXPORT_DIR / f"{name}_bundle.zip"
            with zipfile.ZipFile(zip_file, "w") as zf:
                zf.write(crt, arcname=f"{name}.crt")
                if key.exists():
                    zf.write(key, arcname=f"{name}.key")
                if CA_CERT.exists():
                    zf.write(CA_CERT, arcname="rootCA.crt")
                zf.write(fullchain_file, arcname=f"{name}_fullchain.pem")

            out_file = zip_file

        else:
            return None, f"Unsupported format: {fmt}"

        return out_file, f"Exported {name} as {fmt}"
    except subprocess.CalledProcessError as e:
        return None, f"Error exporting: {e}"

def revoke_cert(name: str):
    crt = CERTS_DIR / f"{name}.crt"
    crl = CA_DIR / "crl.pem"

    if not crt.exists():
        return False, "Certificate not found"

    try:
        subprocess.run(
            ["openssl", "ca",
             "-config", str(OPENSSL_CNF),
             "-revoke", str(crt)],
            check=True
        )
        subprocess.run(
            ["openssl", "ca",
             "-config", str(OPENSSL_CNF),
             "-gencrl",
             "-out", str(crl)],
            check=True
        )
        return True, f"{name} revoked. CRL updated."
    except subprocess.CalledProcessError as e:
        return False, f"Revocation failed: {e}"

