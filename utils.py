import subprocess
from pathlib import Path
from datetime import datetime
import yaml
import zipfile

# --- Directories ---
BASE_DIR = Path(".")                     # project root
CA_DIR = BASE_DIR / "ca"                 # directory for CA keys, certs, config
CERTS_DIR = BASE_DIR / "certs"           # directory for issued certs
EXPORT_DIR = BASE_DIR / "exports"        # directory for exported cert bundles

# Ensure directories exist
for d in [CA_DIR, CERTS_DIR, EXPORT_DIR]:
    d.mkdir(exist_ok=True)

# File paths for CA assets and metadata
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
    "days": 365,              # default cert validity
    "default_password": ""    # used for PKCS12/JKS exports
}

# Load saved metadata if present, otherwise use defaults
if META_FILE.exists():
    with open(META_FILE) as f:
        metadata = yaml.safe_load(f)
else:
    metadata = default_meta.copy()

# --- Helpers ---
def save_metadata(data):
    """Write metadata back to metadata.yaml."""
    with open(META_FILE, "w") as f:
        yaml.safe_dump(data, f)

def create_root_ca():
    """Generate a new Root CA (private key + self-signed certificate)."""
    # Initialize CA database and bookkeeping files if missing
    (CA_DIR / "index.txt").touch(exist_ok=True)
    if not (CA_DIR / "serial").exists():
        (CA_DIR / "serial").write_text("1000\n")
    if not (CA_DIR / "crlnumber").exists():
        (CA_DIR / "crlnumber").write_text("1000\n")

    # Generate CA private key
    subprocess.run(["openssl", "genrsa", "-out", str(CA_KEY), "4096"], check=True)

    # Build subject string from metadata
    subj = f"/C={metadata['country']}/ST={metadata['state']}/L={metadata['locality']}/O={metadata['org']}/OU=CA/CN=CozyRoot"

    # Generate self-signed root certificate
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
    """Sign a CSR with the Root CA and embed SAN (DNS/IP)."""
    cert_file = CERTS_DIR / f"{out_name}.crt"
    ext_file = CERTS_DIR / f"{out_name}_ext.cnf"

    # Build SAN extension
    san_entries = []
    if dns_name:
        san_entries.append(f"DNS:{dns_name}")
    if ip_addr:
        san_entries.append(f"IP:{ip_addr}")

    # Write extension config file
    with open(ext_file, "w") as f:
        f.write("[ v3_req ]\n")
        f.write("subjectAltName=" + ",".join(san_entries) + "\n")

    # Call openssl ca to sign the CSR
    subprocess.run(
        [
            "openssl", "ca",
            "-config", str(OPENSSL_CNF),
            "-extensions", "v3_req",
            "-extfile", str(ext_file),
            "-in", str(csr_file),
            "-out", str(cert_file),
            "-batch"   # suppress interactive prompts
        ],
        check=True
    )
    return cert_file

def generate_cert(dns_name: str, ip_addr: str, self_sign: bool = True):
    """Generate a new keypair, CSR, and optionally a signed certificate."""
    key_file = CERTS_DIR / f"{dns_name}.key"
    csr_file = CERTS_DIR / f"{dns_name}.csr"
    cert_file = CERTS_DIR / f"{dns_name}.crt"

    # Build subject
    subj = f"/C={metadata['country']}/ST={metadata['state']}/L={metadata['locality']}/O={metadata['org']}/OU={metadata['ou']}/CN={dns_name}"

    # Build SAN string for CSR
    san_entries = []
    if dns_name:
        san_entries.append(f"DNS:{dns_name}")
    if ip_addr:
        san_entries.append(f"IP:{ip_addr}")
    san_str = ",".join(san_entries)

    # Generate private key
    subprocess.run(["openssl", "genrsa", "-out", str(key_file), "2048"], check=True)

    # Generate CSR, including SANs if present
    csr_cmd = [
        "openssl", "req", "-new",
        "-key", str(key_file),
        "-subj", subj,
        "-out", str(csr_file)
    ]
    if san_entries:
        csr_cmd.extend(["-addext", f"subjectAltName={san_str}"])
    subprocess.run(csr_cmd, check=True)

    # Optionally sign with Root CA
    if self_sign:
        sign_csr(csr_file, dns_name, dns_name, ip_addr)
        return key_file, csr_file, cert_file
    else:
        # return key + CSR only (unsigned)
        return key_file, csr_file, None

def get_cert_expiry(cert_file: Path):
    """Parse certificate expiration date with OpenSSL."""
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
    """Export certificate in various formats (PEM, DER, PKCS12, JKS, bundle)."""
    crt = CERTS_DIR / f"{name}.crt"
    key = CERTS_DIR / f"{name}.key"
    out_file = EXPORT_DIR / f"{name}.{fmt.lower()}"

    if not crt.exists():
        return None, "Missing certificate file"

    try:
        if fmt.upper() == "PEM":
            # Concatenate key + cert + CA cert
            parts = []
            if key.exists():
                parts.append(key.read_text())
            parts.append(crt.read_text())
            if CA_CERT.exists():
                parts.append(CA_CERT.read_text())
            out_file.write_text("\n".join(parts))

        elif fmt.upper() == "DER":
            # Binary encoding of cert only
            subprocess.run(
                ["openssl", "x509", "-in", str(crt), "-outform", "der", "-out", str(out_file)],
                check=True
            )

        elif fmt.upper() == "PKCS12":
            # Export to .p12 container (cert + key + CA)
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
            # Convert P12 → JKS with keytool
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
            # Create ZIP with cert, key, CA, and fullchain
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
    """Revoke a certificate and update CRL."""
    crt = CERTS_DIR / f"{name}.crt"
    crl = CA_DIR / "crl.pem"

    if not crt.exists():
        return False, "Certificate not found"

    try:
        # Mark cert as revoked
        subprocess.run(
            ["openssl", "ca",
             "-config", str(OPENSSL_CNF),
             "-revoke", str(crt)],
            check=True
        )
        # Regenerate CRL
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
