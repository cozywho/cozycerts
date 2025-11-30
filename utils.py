import subprocess
from pathlib import Path
from datetime import datetime
import yaml
import zipfile
import re
import shutil

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

# Load metadata safely with fallback merging
if META_FILE.exists():
    with open(META_FILE) as f:
        stored = yaml.safe_load(f) or {}
    metadata = {**default_meta, **stored}
else:
    metadata = default_meta.copy()


# --- App-level helpers ---
def save_metadata(data):
    with open(META_FILE, "w") as f:
        yaml.safe_dump(data, f)


def guess_mime(filename: str):
    ext = filename.lower().split(".")[-1]
    return {
        "crt": "application/x-x509-ca-cert",
        "pem": "application/x-pem-file",
        "der": "application/x-x509-ca-cert",
        "p12": "application/x-pkcs12",
        "pfx": "application/x-pkcs12",
        "jks": "application/octet-stream",
        "zip": "application/zip",
        "key": "text/plain",
        "csr": "text/plain"
    }.get(ext, "application/octet-stream")


def safe_name(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9.-]', '_', name or "cert")


# --- Per-cert metadata helpers ---
def write_cert_metadata(cert_dir: Path, data: dict):
    meta_file = cert_dir / "metadata.yaml"
    with open(meta_file, "w") as f:
        yaml.safe_dump(data, f)


def load_cert_metadata(cert_dir: Path):
    meta_file = cert_dir / "metadata.yaml"
    if meta_file.exists():
        with open(meta_file) as f:
            return yaml.safe_load(f) or {}
    return {}


# --- CA helpers ---
def create_root_ca():
    if not OPENSSL_CNF.exists():
        raise FileNotFoundError("Missing openssl.cnf inside ca/")

    # init DB if not present
    (CA_DIR / "index.txt").touch(exist_ok=True)
    if not (CA_DIR / "serial").exists():
        (CA_DIR / "serial").write_text("1000\n")
    if not (CA_DIR / "crlnumber").exists():
        (CA_DIR / "crlnumber").write_text("1000\n")

    # ensure newcerts/ exists (required by openssl)
    (CA_DIR / "newcerts").mkdir(exist_ok=True)

    subprocess.run(["openssl", "genrsa", "-out", str(CA_KEY), "4096"], check=True)
    subj = (
        f"/C={metadata['country']}/ST={metadata['state']}/L={metadata['locality']}"
        f"/O={metadata['org']}/OU=CA/CN=CozyRoot"
    )
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
    # NO initial CRL here; we create CRL after first cert issuance


def _reset_ca():
    # wipe everything under ca/ except openssl.cnf
    for f in CA_DIR.glob("*"):
        if f.name == "openssl.cnf":
            continue
        if f.is_file():
            f.unlink()
        elif f.is_dir():
            shutil.rmtree(f)

    # re-init OpenSSL bookkeeping
    (CA_DIR / "index.txt").write_text("")
    (CA_DIR / "serial").write_text("1000\n")
    (CA_DIR / "crlnumber").write_text("1000\n")

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


# --- Cert / CSR generation + signing (multi-SAN aware) ---
def sign_csr(
    csr_file: Path,
    out_name: str,
    dns_list: list[str],
    ip_list: list[str],
    cn: str | None = None
) -> Path:
    if not OPENSSL_CNF.exists():
        raise FileNotFoundError("Missing openssl.cnf inside ca/")

    base = safe_name(out_name)
    cert_dir = CERTS_DIR / base
    cert_dir.mkdir(exist_ok=True)

    cert_file = cert_dir / "cert.crt"
    ext_file = cert_dir / "ext.cnf"

    san_entries: list[str] = []
    for d in dns_list or []:
        san_entries.append(f"DNS:{d}")
    for ip in ip_list or []:
        san_entries.append(f"IP:{ip}")

    with open(ext_file, "w") as f:
        f.write("[ v3_req ]\n")
        if san_entries:
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

    ext_file.unlink(missing_ok=True)

    # metadata
    expiry = get_cert_expiry(cert_file)
    expiry_str = expiry.strftime("%Y-%m-%dT%H:%M:%SZ") if expiry else None
    cn_value = cn or (dns_list[0] if dns_list else base)

    meta = {
        "name": base,
        "cn": cn_value,
        "dns": dns_list or [],
        "ips": ip_list or [],
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires": expiry_str,
        "signed_by": "CozyRoot",
        "revoked": False,
    }
    write_cert_metadata(cert_dir, meta)

    # ensure CRL exists after first issued cert; ignore failures
    crl_file = CA_DIR / "crl.pem"
    if not crl_file.exists():
        try:
            subprocess.run(
                ["openssl", "ca", "-config", str(OPENSSL_CNF), "-gencrl", "-out", str(crl_file)],
                check=True
            )
        except subprocess.CalledProcessError:
            pass

    return cert_file


def generate_cert(
    cn: str,
    dns_list: list[str],
    ip_list: list[str],
    self_sign: bool = True
):
    # derive a base name from CN or first DNS entry
    base_name_source = cn or (dns_list[0] if dns_list else None)
    base = safe_name(base_name_source or "cert")

    cert_dir = CERTS_DIR / base
    cert_dir.mkdir(exist_ok=True)

    key_file = cert_dir / "key.pem"
    csr_file = cert_dir / "req.csr"

    subject_cn = base_name_source or base
    subj = (
        f"/C={metadata['country']}/ST={metadata['state']}/L={metadata['locality']}"
        f"/O={metadata['org']}/OU={metadata['ou']}/CN={subject_cn}"
    )

    subprocess.run(["openssl", "genrsa", "-out", str(key_file), "2048"], check=True)
    subprocess.run(
        ["openssl", "req", "-new", "-key", str(key_file), "-subj", subj, "-out", str(csr_file)],
        check=True
    )

    if self_sign:
        cert_file = sign_csr(csr_file, base, dns_list, ip_list, cn=subject_cn)
        return key_file, csr_file, cert_file

    # CSR-only mode: still track metadata
    meta = {
        "name": base,
        "cn": subject_cn,
        "dns": dns_list or [],
        "ips": ip_list or [],
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires": None,
        "signed_by": None,
        "revoked": False,
    }
    write_cert_metadata(cert_dir, meta)
    return key_file, csr_file, None


def export_certificate(name: str, fmt: str, password: str = None):
    base = safe_name(name)
    cert_dir = CERTS_DIR / base
    crt = cert_dir / "cert.crt"
    key = cert_dir / "key.pem"
    out_file = EXPORT_DIR / f"{base}.{fmt.lower()}"

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
                [
                    "openssl", "pkcs12", "-export",
                    "-inkey", str(key), "-in", str(crt),
                    "-certfile", str(CA_CERT),
                    "-out", str(out_file),
                    "-password", f"pass:{password}"
                ],
                check=True
            )

        elif fmt.upper() == "JKS":
            password = password or metadata["default_password"]
            if not password:
                return None, "Password required for JKS export"

            p12_temp = EXPORT_DIR / f"{base}_temp.p12"

            subprocess.run(
                [
                    "openssl", "pkcs12", "-export",
                    "-inkey", str(key), "-in", str(crt),
                    "-certfile", str(CA_CERT),
                    "-out", str(p12_temp),
                    "-password", f"pass:{password}"
                ],
                check=True
            )

            subprocess.run(
                [
                    "keytool", "-importkeystore",
                    "-srckeystore", str(p12_temp), "-srcstoretype", "PKCS12", "-srcstorepass", password,
                    "-destkeystore", str(out_file), "-deststoretype", "JKS", "-deststorepass", password
                ],
                check=True
            )

            p12_temp.unlink(missing_ok=True)

        elif fmt.upper() == "BUNDLE":
            fullchain_file = EXPORT_DIR / f"{base}_fullchain.pem"
            parts = [crt.read_text()]
            if CA_CERT.exists():
                parts.append(CA_CERT.read_text())
            fullchain_file.write_text("\n".join(parts))

            zip_file = EXPORT_DIR / f"{base}_bundle.zip"
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
    base = safe_name(name)
    cert_dir = CERTS_DIR / base
    cert_file = cert_dir / "cert.crt"
    crl = CA_DIR / "crl.pem"

    if not cert_file.exists():
        return False, "Certificate not found"

    try:
        subprocess.run(
            ["openssl", "ca", "-config", str(OPENSSL_CNF), "-revoke", str(cert_file)],
            check=True
        )
        subprocess.run(
            ["openssl", "ca", "-config", str(OPENSSL_CNF), "-gencrl", "-out", str(crl)],
            check=True
        )

        meta = load_cert_metadata(cert_dir)
        meta["revoked"] = True
        write_cert_metadata(cert_dir, meta)

        return True, f"{name} revoked. CRL updated."
    except subprocess.CalledProcessError as e:
        return False, f"Revocation failed: {e}"


# --- Generic inspector ---
def inspect_cert(cert_bytes: bytes, password: str = None):
    temp = BASE_DIR / "temp_inspect"
    temp.mkdir(exist_ok=True)

    tmpfile = temp / "upload.bin"
    tmpfile.write_bytes(cert_bytes)

    # Try PEM/CRT
    result = subprocess.run(
        ["openssl", "x509", "-in", str(tmpfile), "-noout", "-text"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        tmpfile.unlink(missing_ok=True)
        return "X509 (PEM)", result.stdout

    # Try DER
    result = subprocess.run(
        ["openssl", "x509", "-in", str(tmpfile), "-inform", "der", "-noout", "-text"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        tmpfile.unlink(missing_ok=True)
        return "X509 (DER)", result.stdout

    # Try CSR
    result = subprocess.run(
        ["openssl", "req", "-in", str(tmpfile), "-noout", "-text"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        tmpfile.unlink(missing_ok=True)
        return "CSR", result.stdout

    # Try PKCS#12 / PFX
    if password:
        result = subprocess.run(
            [
                "openssl", "pkcs12", "-in", str(tmpfile),
                "-nodes", "-password", f"pass:{password}"
            ],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            tmpfile.unlink(missing_ok=True)
            return "PKCS#12 / PFX", result.stdout

    tmpfile.unlink(missing_ok=True)
    return "Unknown", "Unable to parse certificate or CSR."

