# Sistema de Mensajería Segura Extremo a Extremo (E2EE)

Proyecto final para la asignatura de **Criptología** — Ingeniería Telemática, Universidad Distrital Francisco José de Caldas (2026).

Implementación en Python de un sistema de mensajería cifrada extremo a extremo inspirado en el **Protocolo Signal (X3DH + Ratchet Simétrico)** sobre una arquitectura cliente-servidor de conocimiento cero.


## Arquitectura y primitivas Criptográficas

* **Identidad y firma:** `Ed25519` ($IK_{sig}$) para firmar la *Signed PreKey* ($SPK$) y mitigar ataques de MITM en el directorio del server.
* **Acuerdo de claves (X3DH):** `X25519` ($IK_{dh}$, $SPK$, $EK$), con triple intercambio diffie-hellman y derivacion de clave raiz mediante el `HKDF-SHA256`
* **Ratchet Simétrico(*Forward Secrecy*):** Avance unidireccional por mensaje usando el `HMAC-SHA256` con (`0x01` para la clave de mensaje y `0x02` para la clave de cadena) con destrucción inmediata de claves usadas y control anti-replay por contador
* **Cifrado Autenticado (AEAD):** `AES-256-GCM`vinculado identidades y secuencia como *Associated Data*
* **Almacenamiento y autenticación:** `Argon2ID` (64 MiB, 3 iteraciones y 4 hilos) para bóvedas locales cifradas y contraseñas en servidor, tokens de sesión de 256 bits almacenados como hash `SHA-256`.


## Instalción Local
```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt

```
## Estructura del Proyecto

```text
├── client/
│   ├── crypto_utils.py   # Primitivas: Ed25519, X25519, HKDF, HMAC, AES-256-GCM, Argon2id
│   ├── session.py        # Motor del protocolo: acuerdo X3DH, ratchet simétrico y anti-replay
│   └── cli.py            # Cliente de consola, gestión de bóveda cifrada y Safety Number
├── server/
│   ├── database.py       # Esquema SQLite (bundles públicos, hashes de sesión y buzón cifrado)
│   └── main.py           # API REST en FastAPI (registro, autenticación Bearer y buzón)
├── attacks/
│   └── stride_attacks.py # Simulación y validación de defensas frente a amenazas STRIDE
├── test/                 # Suite de pruebas unitarias y de integración (pytest)
├── Dockerfile            # Imagen del servidor FastAPI con soporte TLS
└── docker-compose.yml    # Orquestación del servicio
```


## Test
* **Pruebas unitarias:** integracion con pytest 
```powershell
.\venv\Scripts\python.exe -m pytest -v
```
* **Simulación de ataques Stride:** Se simulan ataques tipo (Spoofing, Tampering, Replay, Information Disclosure, Elevation of Privilege)
```powershell
.\venv\Scripts\python.exe -m attacks.stride_attacks
```
* **Cifrado TLS:** Genera un cifrado TLS autofirmado local en certs/.. (cert.pem y key.pem) y levanta el servidor
```powershell
mkdir certs -Force
.\venv\Scripts\python.exe -c "import datetime, ipaddress; from cryptography import x509; from cryptography.x509.oid import NameOID; from cryptography.hazmat.primitives import hashes, serialization; from cryptography.hazmat.primitives.asymmetric import rsa; key = rsa.generate_private_key(65537, 2048); name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]); cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc)).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False).sign(key, hashes.SHA256()); open('certs/key.pem', 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())); open('certs/cert.pem', 'wb').write(cert.public_bytes(serialization.Encoding.PEM)); print('Certificado generado en certs/')"
```

```powershell
.\venv\Scripts\python.exe -m uvicorn server.main:app --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem


```
para levantar con docker:
```powershell
docker compose up --build
```

* **Conectar clientes:** en terminales diferentes puedes abrir cuantos clientes desees:
```powershell
$env:SERVER_URL="https://127.0.0.1:8000"
$env:SSL_CERT_FILE="certs\cert.pem"
.\venv\Scripts\python.exe -m client.cli
```
