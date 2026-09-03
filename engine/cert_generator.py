"""
Self-Signed TLS/SSL Certificate Generator Engine.
Generates cryptographically valid local X.509 certificates and RSA private keys for HTTPS servers.
"""

import os
import datetime
from typing import Tuple

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import ipaddress
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def generate_self_signed_cert(
    cert_dir: str = "certs",
    cert_name: str = "cert.pem",
    key_name: str = "key.pem",
) -> Tuple[str, str]:
    """
    Generates a self-signed TLS/SSL certificate and private key for local HTTPS web servers.
    Subject Alternative Names (SAN) include localhost, 127.0.0.1, and ::1.
    """
    os.makedirs(cert_dir, exist_ok=True)
    cert_path = os.path.join(cert_dir, cert_name)
    key_path = os.path.join(cert_dir, key_name)

    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("The 'cryptography' library is required to generate TLS certificates.")

    # 1. Generate RSA Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Build Subject & Issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Security"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NKAT AI Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    # 3. Build Certificate with SANs
    now = datetime.datetime.now(datetime.timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("::1")),
            ]),
            critical=False,
        )
    )

    cert = cert_builder.sign(private_key, hashes.SHA256())

    # 4. Write Private Key file
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # 5. Write Certificate file
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] TLS Certificate generated successfully at: {cert_path}")
    print(f"[+] Private Key generated successfully at: {key_path}")

    return cert_path, key_path


if __name__ == "__main__":
    generate_self_signed_cert()
