# 🛡️ ShieldNet – Secure TCP Tunnel with TLS

**ShieldNet** is a lightweight TCP tunnel written in Python that uses TLS encryption to securely forward traffic between a local client and a remote server. It behaves like a minimal VPN over TCP.

---

## 🚀 Features

- End-to-end encryption using TLS
- Fully implemented in Python (standard library only)
- Local port forwarding over secure tunnel
- Self-signed or trusted certificate support
- CLI-based, cross-platform (Linux, Windows, macOS)

---

## 🧰 Requirements

- Python 3.8+
- OpenSSL (to generate certificates)

---

## 🔑 Generate TLS Certificates

```bash
openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
cp cert.pem ca.pem  # For client trust
```

---

## 🖥️ Running the Server

```bash
python server.py \
  --listen-port 8443 \
  --forward-host 127.0.0.1 \
  --forward-port 80 \
  --cert cert.pem \
  --key key.pem
```

This will accept TLS connections on port 8443 and forward them to `127.0.0.1:80`.

---

## 💻 Running the Client

```bash
python client.py \
  --listen-port 1080 \
  --remote-host <server-ip> \
  --remote-port 8443 \
  --ca ca.pem
```

This will listen on local port 1080 and forward traffic through the TLS tunnel to the remote server.

---

## 📈 How It Works

```
[User App] → TCP → [Client.py] → TLS → [Server.py] → TCP → [Target Service]
```

* Client accepts local connections
* Encrypts and tunnels data to the server
* Server decrypts and forwards to the destination

---

## 🔐 Security Notes

* TLS ensures confidentiality and authenticity
* Only trusted certificates will be accepted
* Mutual TLS (2-way auth) can be added

---

## 🛠️ Optional Features

* Shared secret (password) authentication
* AsyncIO for better concurrency
* JSON config file support

---

## 📄 License

MIT License – Use, modify, and share freely.

---

## 👤 Author

Project made for a networking course / cybersecurity lab.
