"""
generate_certs.py — Generate a self-signed TLS certificate for the OTPMail relay.

For development / local use only.
In production, obtain a certificate from a trusted CA (e.g., Let's Encrypt).

NOTE: For post-quantum transport security, the production TLS stack should use
      X25519Kyber768 hybrid key exchange (OQS-OpenSSL or BoringSSL-OQS).
"""

import os
import datetime
import argparse

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress
except ImportError:
    print("cryptography library required: pip install cryptography")
    raise SystemExit(1)


def generate(cert_path: str = "server.crt", key_path: str = "server.key",
             hostname: str = "localhost", days: int = 3650) -> None:
    # RSA-4096 key (ECDSA P-256 is a leaner alternative for production)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OTPMail Relay"),
    ])

    san = x509.SubjectAlternativeName([
        x509.DNSName(hostname),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
        .add_extension(san, critical=False)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(priv, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Certificate  : {cert_path}")
    print(f"Private key  : {key_path}  (chmod 600)")
    print(f"Valid for    : {days} days")
    print(f"SANs         : {hostname}, localhost, 127.0.0.1")
    print()
    print("Start the relay server with:")
    print(f"  python server.py --cert {cert_path} --key {key_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate self-signed TLS cert for OTPMail relay")
    ap.add_argument("--cert",     default="server.crt")
    ap.add_argument("--key",      default="server.key")
    ap.add_argument("--hostname", default="localhost")
    ap.add_argument("--days",     type=int, default=3650)
    args = ap.parse_args()
    generate(args.cert, args.key, args.hostname, args.days)
