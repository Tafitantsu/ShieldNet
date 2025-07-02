import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from ipaddress import IPv4Address

CERT_DIR = "certs"
os.makedirs(CERT_DIR, exist_ok=True)

def save_key(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def generate_ca():
    key = generate_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"MG"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyCompany"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"MyTestCA"),
    ])
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow() - timedelta(days=1))\
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .sign(key, hashes.SHA256())

    save_key(key, f"{CERT_DIR}/ca.key")
    save_cert(cert, f"{CERT_DIR}/ca.crt")
    return key, cert

def generate_cert(cn, san_dns=[], san_ips=[], issuer_key=None, issuer_cert=None, name_prefix="entity"):
    key = generate_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"MG"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyCompany"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    alt_names = []
    for dns in san_dns:
        alt_names.append(x509.DNSName(dns))
    for ip in san_ips:
        alt_names.append(x509.IPAddress(IPv4Address(ip)))

    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer_cert.subject)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow() - timedelta(days=1))\
        .not_valid_after(datetime.utcnow() + timedelta(days=825))\
        .add_extension(
            x509.SubjectAlternativeName(alt_names),
            critical=False
        )\
        .sign(issuer_key, hashes.SHA256())

    save_key(key, f"{CERT_DIR}/{name_prefix}.key")
    save_cert(cert, f"{CERT_DIR}/{name_prefix}.crt")

if __name__ == "__main__":
    # 1. CA
    ca_key, ca_cert = generate_ca()

    # 2. Server cert (SAN = tunnel-server, localhost, 127.0.0.1)
    generate_cert(
        cn="tunnel-server",
        san_dns=["tunnel-server", "localhost"],
        san_ips=["127.0.0.1"],
        issuer_key=ca_key,
        issuer_cert=ca_cert,
        name_prefix="server"
    )

    # 3. Client cert (CN = client1)
    generate_cert(
        cn="client1",
        san_dns=["client1"],
        issuer_key=ca_key,
        issuer_cert=ca_cert,
        name_prefix="client"
    )

    print("✅ Certs created in ./certs/: ca.crt, ca.key, server.crt/key, client.crt/key")
