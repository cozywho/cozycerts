import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple
import yaml
import zipfile
import re
import shutil

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

default_meta = {
    "country": "US",
    "state": "NC",
    "locality": "Lab",
    "org": "CozyCerts",
    "ou": "General",
    "days": 365,
    "default_password": "",
}

if META_FILE.exists():
    with open(META_FILE) as f:
        stored = yaml.safe_load(f) or {}
    metadata = {**default_meta, **stored}
else:
    metadata = default_meta.copy()


def save_metadata(data: dict) -> None:
    with open(META_FILE, "w") as f:
        yaml.safe_dump(data, f)


def guess_mime(filename: str) -> str:
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
        "csr": "text/plain",
    }.get(ext, "application/octet-stream")


def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]", "_", name or "cert")


def write_cert_metadata(cert_dir: Path, data: dict) -> None:
    with open(cert_dir / "metadata.yaml", "w") as f:
        yaml.safe_dump(data, f)


def load_cert_metadata(cert_dir: Path) -> dict:
    mf = cert_dir / "metadata.yaml"
    if mf.exists():
        with open(mf) as f:
            return yaml.safe_load(f) or {}
    return {}


def create_root_ca() -> None:
    if not OPENSSL_CNF.exists():
        raise FileNotFoundError("Missing openssl.cnf inside ca/")

    (CA_DIR / "index.txt").touch(exist_ok=True)
    if not (CA_DIR / "serial").exists():
        (CA_DIR / "serial").write_text("1000\n")
    if not (CA_DIR / "crlnumber").exists():
        (CA_DIR / "crlnumber").write_text("1000\n")

    (CA_DIR / "newcerts").mkdir(exist_ok=True)

    subprocess.run(["openssl", "genrsa", "-out", str(CA_KEY), "4096"], check=True)

    subj = (
        f"/C={metadata['country']}/ST={metadata['state']}/L={metadata['locality']}"
        f"/O={metadata['org']}/OU=CA/CN=CozyRoot"
    )

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-nodes",
            "-key",
            str(CA_KEY),
            "-sha256",
            "-days",
            str(metadata["days"]),
            "-subj",
            subj,
            "-out",
            str(CA_CERT),
        ],
        check=True,
    )


def _reset_ca() -> None:
    for f in CA_DIR.glob("*"):
        if f.name == "openssl.cnf":
            continue
        if f.is_dir():
            shutil.rmtree(f)
        else:
            f.unlink()

    (CA_DIR / "index.txt").write_text("")
    (CA_DIR / "serial").write_text("1000\n")
    (CA_DIR / "crlnumber").write_text("1000\n")
    (CA_DIR / "newcerts").mkdir(parents=True, exist_ok=True)

    if CERTS_DIR.exists():
        shutil.rmtree(CERTS_DIR)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    crl_file = CA_DIR / "crl.pem"
    if crl_file.exists():
        crl_file.unlink()


def get_cert_expiry(cert_file: Path) -> Optional[datetime]:
    try:
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", str(cert_file)],
            capture_output=True,
            text=True,
            check=True,
        )
        d = result.stdout.strip().split("=", 1)[1].strip()
        return datetime.strptime(d, "%b %d %H:%M:%S %Y GMT")
    except Exception:
        return None


def sign_csr(
    csr_file: Path,
    out_name: str,
    dns_list: List[str],
    ip_list: List[str],
    cn: Optional[str] = None,
) -> Path:
    if not OPENSSL_CNF.exists():
        raise FileNotFoundError("Missing openssl.cnf inside ca/")

    base = safe_name(out_name)
    cert_dir = CERTS_DIR / base
    cert_dir.mkdir(exist_ok=True)

    cert_file = cert_dir / "cert.crt"
    ext_file = cert_dir / "ext.cnf"

    san: List[str] = []
    for d in dns_list or []:
        san.append(f"DNS:{d}")
    for ip in ip_list or []:
        san.append(f"IP:{ip}")

    with open(ext_file, "w") as f:
        f.write("[ v3_req ]\n")
        if san:
            f.write("subjectAltName=" + ",".join(san) + "\n")

    subprocess.run(
        [
            "openssl",
            "ca",
            "-config",
            str(OPENSSL_CNF),
            "-extensions",
            "v3_req",
            "-extfile",
            str(ext_file),
            "-in",
            str(csr_file),
            "-out",
            str(cert_file),
            "-batch",
        ],
        check=True,
    )

    ext_file.unlink(missing_ok=True)

    expiry = get_cert_expiry(cert_file)
    expiry_str = expiry.strftime("%Y-%m-%dT%H:%M:%SZ") if expiry else None
    cn_val = cn or (dns_list[0] if dns_list else base)

    meta = {
        "name": base,
        "cn": cn_val,
        "dns": dns_list or [],
        "ips": ip_list or [],
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires": expiry_str,
        "signed_by": "CozyRoot",
        "revoked": False,
    }
    write_cert_metadata(cert_dir, meta)

    crl_file = CA_DIR / "crl.pem"
    if not crl_file.exists():
        try:
            subprocess.run(
                [
                    "openssl",
                    "ca",
                    "-config",
                    str(OPENSSL_CNF),
                    "-gencrl",
                    "-out",
                    str(crl_file),
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            pass

    return cert_file


def generate_cert(
    cn: Optional[str],
    dns_list: List[str],
    ip_list: List[str],
    self_sign: bool = True,
):
    base_src = cn or (dns_list[0] if dns_list else None)
    base = safe_name(base_src or "cert")

    cert_dir = CERTS_DIR / base
    cert_dir.mkdir(exist_ok=True)

    key_file = cert_dir / "key.pem"
    csr_file = cert_dir / "req.csr"

    subject_cn = base_src or base

    subj = (
        f"/C={metadata['country']}/ST={metadata['state']}/L={metadata['locality']}"
        f"/O={metadata['org']}/OU={metadata['ou']}/CN={subject_cn}"
    )

    subprocess.run(["openssl", "genrsa", "-out", str(key_file), "2048"], check=True)
    subprocess.run(
        ["openssl", "req", "-new", "-key", str(key_file), "-subj", subj, "-out", str(csr_file)],
        check=True,
    )

    if self_sign:
        cert_file = sign_csr(csr_file, base, dns_list, ip_list, cn=subject_cn)
        return key_file, csr_file, cert_file

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


def export_certificate(name: str, fmt: str, password: Optional[str] = None) -> Tuple[Optional[Path], str]:
    base = safe_name(name)
    cert_dir = CERTS_DIR / base
    crt = cert_dir / "cert.crt"
    key = cert_dir / "key.pem"
    out_file = EXPORT_DIR / f"{base}.{fmt.lower()}"

    if not crt.exists():
        return None, "Missing certificate file"

    try:
        f = fmt.upper()

        if f == "PEM":
            parts: List[str] = []
            if key.exists():
                parts.append(key.read_text())
            parts.append(crt.read_text())
            if CA_CERT.exists():
                parts.append(CA_CERT.read_text())
            out_file.write_text("\n".join(parts))

        elif f == "DER":
            subprocess.run(
                ["openssl", "x509", "-in", str(crt), "-outform", "der", "-out", str(out_file)],
                check=True,
            )

        elif f == "PKCS12":
            password = password or metadata["default_password"]
            if not password:
                return None, "Password required"
            subprocess.run(
                [
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-inkey",
                    str(key),
                    "-in",
                    str(crt),
                    "-certfile",
                    str(CA_CERT),
                    "-out",
                    str(out_file),
                    "-password",
                    f"pass:{password}",
                ],
                check=True,
            )

        elif f == "JKS":
            password = password or metadata["default_password"]
            if not password:
                return None, "Password required"

            p12tmp = EXPORT_DIR / f"{base}_tmp.p12"
            subprocess.run(
                [
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-inkey",
                    str(key),
                    "-in",
                    str(crt),
                    "-certfile",
                    str(CA_CERT),
                    "-out",
                    str(p12tmp),
                    "-password",
                    f"pass:{password}",
                ],
                check=True,
            )

            subprocess.run(
                [
                    "keytool",
                    "-importkeystore",
                    "-srckeystore",
                    str(p12tmp),
                    "-srcstoretype",
                    "PKCS12",
                    "-srcstorepass",
                    password,
                    "-destkeystore",
                    str(out_file),
                    "-deststoretype",
                    "JKS",
                    "-deststorepass",
                    password,
                ],
                check=True,
            )

            p12tmp.unlink(missing_ok=True)

        elif f == "BUNDLE":
            fc = EXPORT_DIR / f"{base}_fullchain.pem"
            parts = [crt.read_text()]
            if CA_CERT.exists():
                parts.append(CA_CERT.read_text())
            fc.write_text("\n".join(parts))

            zip_path = EXPORT_DIR / f"{base}_bundle.zip"
            with zipfile.ZipFile(zip_path, "w") as z:
                z.write(crt, arcname=f"{name}.crt")
                if key.exists():
                    z.write(key, arcname=f"{name}.key")
                if CA_CERT.exists():
                    z.write(CA_CERT, arcname="rootCA.crt")
                z.write(fc, arcname=f"{name}_fullchain.pem")

            out_file = zip_path

        else:
            return None, f"Unsupported format {fmt}"

        return out_file, "OK"

    except subprocess.CalledProcessError as e:
        return None, f"Error: {e}"


def revoke_cert(name: str) -> Tuple[bool, str]:
    base = safe_name(name)
    cert_dir = CERTS_DIR / base
    cert_file = cert_dir / "cert.crt"
    crl = CA_DIR / "crl.pem"

    if not cert_file.exists():
        return False, "Certificate not found"

    try:
        subprocess.run(
            ["openssl", "ca", "-config", str(OPENSSL_CNF), "-revoke", str(cert_file)],
            check=True,
        )
        subprocess.run(
            ["openssl", "ca", "-config", str(OPENSSL_CNF), "-gencrl", "-out", str(crl)],
            check=True,
        )

        meta = load_cert_metadata(cert_dir)
        meta["revoked"] = True
        write_cert_metadata(cert_dir, meta)

        return True, "OK"
    except subprocess.CalledProcessError as e:
        return False, f"Revocation failed: {e}"


def inspect_cert(cert_bytes: bytes, password: Optional[str] = None):
    temp = BASE_DIR / "temp_inspect"
    temp.mkdir(exist_ok=True)

    tmp = temp / "upload.bin"
    tmp.write_bytes(cert_bytes)

    r = subprocess.run(
        ["openssl", "x509", "-in", str(tmp), "-noout", "-text"],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        tmp.unlink(missing_ok=True)
        return "X509 (PEM)", r.stdout

    r = subprocess.run(
        ["openssl", "x509", "-in", str(tmp), "-inform", "der", "-noout", "-text"],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        tmp.unlink(missing_ok=True)
        return "X509 (DER)", r.stdout

    r = subprocess.run(
        ["openssl", "req", "-in", str(tmp), "-noout", "-text"],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        tmp.unlink(missing_ok=True)
        return "CSR", r.stdout

    if password:
        r = subprocess.run(
            ["openssl", "pkcs12", "-in", str(tmp), "-nodes", "-password", f"pass:{password}"],
            capture_output=True,
            text=True,
        )
        if r.returncode == 0:
            tmp.unlink(missing_ok=True)
            return "PKCS#12/PFX", r.stdout

    tmp.unlink(missing_ok=True)
    return "Unknown", "Unable to parse."

