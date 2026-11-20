"""
Módulo: client/cli.py
Propósito: Cliente interactivo de consola con bóveda cifrada local, X3DH, Ratchet,
           directorio de contactos [VERIFICADO / NO VERIFICADO], QR en consola e historial.
"""

import base64
import getpass
import hmac
import os
from datetime import datetime
from typing import Dict, List, Optional

import httpx

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

try:
    import qrcode
except ImportError:
    qrcode = None

from client.crypto_utils import (
    compute_safety_number,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    load_encrypted_vault,
    save_encrypted_vault,
    sign_prekey,
)
from client.session import ChatSession, EncryptedPacket, PreKeyBundle

SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:8000")
# Certificado autofirmado del servidor (Docker/TLS). Si no se define, se usa la CA del sistema.
SSL_CERT_FILE = os.getenv("SSL_CERT_FILE")

QR_PREFIX = "E2EE-SN"
TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def priv_to_b64(priv_key) -> str:
    raw = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return b64e(raw)


def _http_kwargs() -> dict:
    """Opciones TLS para httpx: confía en el certificado del servidor si se configuró."""
    return {"verify": SSL_CERT_FILE} if SSL_CERT_FILE else {}


def _now() -> str:
    return datetime.now().strftime(TS_FORMAT)


def build_qr_payload(user_a: str, user_b: str, safety_number: str) -> str:
    """
    Contenido del QR de verificación fuera de banda.
    Los usuarios se ordenan para que ambos extremos generen exactamente el mismo QR.
    """
    first, second = sorted([user_a, user_b])
    return f"{QR_PREFIX}:{first}:{second}:{safety_number.replace(' ', '')}"


def print_qr_console(payload: str) -> None:
    """Dibuja un código QR en la terminal para comparar el Safety Number en persona."""
    if qrcode is None:
        print("  (Instala 'qrcode' para visualizar el código QR en consola)")
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    try:
        qr.print_ascii(invert=True)
    except UnicodeEncodeError:
        # Consolas sin UTF-8 no pueden pintar los bloques del QR
        print("  (Tu consola no soporta UTF-8; compara el texto del QR manualmente)")
    print(f"  Contenido QR: {payload}")


class SecureClient:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.vault_path = f"{username}_vault.json"
        self.token: str = ""
        self.vault: Dict = {}
        self.sessions: Dict[str, ChatSession] = {}

    # ------------------------------------------------------------------
    # Persistencia de la bóveda
    # ------------------------------------------------------------------
    def _save_state(self) -> None:
        """ Guarda claves privadas, contactos conocidos/verificados,
            estado del ratchet e historial cifrados
        """
        serialized_sessions = {}
        for peer, sess in self.sessions.items():
            serialized_sessions[peer] = {
                "local_ik_dh_pub": b64e(sess.local_ik_dh_pub),
                "peer_ik_dh_pub": b64e(sess.peer_ik_dh_pub),
                "chain_key": b64e(sess.chain_key),
                "ephemeral_pub": b64e(sess.ephemeral_pub),
                "send_counter": sess.send_counter,
                "received_counters": list(sess.received_counters),
            }
        self.vault["sessions"] = serialized_sessions
        save_encrypted_vault(self.vault_path, self.password, self.vault)

    def _restore_sessions(self) -> None:
        """ Reconstruye en memoria las sesiones
            activas guardadas en la bóveda
        """
        for peer, data in self.vault.get("sessions", {}).items():
            self.sessions[peer] = ChatSession(
                local_ik_dh_pub=b64d(data["local_ik_dh_pub"]),
                peer_ik_dh_pub=b64d(data["peer_ik_dh_pub"]),
                chain_key=b64d(data["chain_key"]),
                ephemeral_pub=b64d(data["ephemeral_pub"]),
                send_counter=data["send_counter"],
                received_counters=set(data["received_counters"]),
            )

    def _ensure_vault_schema(self) -> None:
        """Compatibilidad con bóvedas creadas antes del directorio de contactos."""
        self.vault.setdefault("known_contacts", {})
        self.vault.setdefault("verified_contacts", [])
        self.vault.setdefault("sessions", {})
        self.vault.setdefault("history", [])

    # ------------------------------------------------------------------
    # Fases 1 y 2: registro y login
    # ------------------------------------------------------------------
    def register(self) -> None:
        """ Fase 1
                Genera identidades Ed25519/X25519,
                firma SPK, registra y cifra bóveda
        """

        if os.path.exists(self.vault_path):
            raise FileExistsError(f"Ya existe una bóveda local para '{self.username}'.")

        ik_sig_priv, ik_sig_pub = generate_ed25519_keypair()
        ik_dh_priv, ik_dh_pub = generate_x25519_keypair()
        spk_priv, spk_pub = generate_x25519_keypair()
        spk_sig = sign_prekey(ik_sig_priv, spk_pub)

        payload = {
            "username": self.username,
            "password": self.password,
            "ik_sig_pub": b64e(ik_sig_pub),
            "ik_dh_pub": b64e(ik_dh_pub),
            "spk_pub": b64e(spk_pub),
            "spk_sig": b64e(spk_sig),
        }

        res = httpx.post(f"{SERVER_URL}/register", json=payload, **_http_kwargs())
        if res.status_code != 201:
            raise RuntimeError(f"Error al registrar en servidor: {res.text}")

        self.vault = {
            "keys": {
                "ik_sig_priv": priv_to_b64(ik_sig_priv),
                "ik_sig_pub": b64e(ik_sig_pub),
                "ik_dh_priv": priv_to_b64(ik_dh_priv),
                "ik_dh_pub": b64e(ik_dh_pub),
                "spk_priv": priv_to_b64(spk_priv),
                "spk_pub": b64e(spk_pub),
            },
            "known_contacts": {},     # {usuario: ik_dh_pub_b64}  (Identity Pinning / TOFU)
            "verified_contacts": [],  # Contactos verificados vía Safety Number / QR
            "sessions": {},
            "history": [],
        }
        self._save_state()
        print(f"[OK] Usuario '{self.username}' registrado y bóveda cifrada en '{self.vault_path}'.")

    def login(self) -> None:
        """ Fase 2
                Descifra bóveda local y solicita token de sesión
                de 256 bits al servidor
        """

        try:
            self.vault = load_encrypted_vault(self.vault_path, self.password)
        except FileNotFoundError:
            raise FileNotFoundError("No existe bóveda local. Regístrate primero.")
        except InvalidTag:
            raise ValueError("Contraseña local incorrecta: imposible descifrar la bóveda.")

        self._ensure_vault_schema()

        res = httpx.post(
            f"{SERVER_URL}/login",
            json={"username": self.username, "password": self.password},
            **_http_kwargs(),
        )
        if res.status_code != 200:
            raise RuntimeError(f"Error de autenticación en servidor: {res.text}")

        self.token = res.json()["access_token"]
        self._restore_sessions()
        print(f"[OK] Sesión iniciada como '{self.username}'. Token válido por 1 hora.")

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def _fetch_bundle(self, peer: str) -> Optional[PreKeyBundle]:
        """Descarga el PreKey Bundle público de un usuario desde el directorio del servidor."""
        res = httpx.get(f"{SERVER_URL}/keys/{peer}", headers=self._auth_headers(), **_http_kwargs())
        if res.status_code != 200:
            print(f"[ERROR] No se pudo obtener el bundle de '{peer}': {res.text}")
            return None
        data = res.json()
        return PreKeyBundle(
            ik_sig_pub=b64d(data["ik_sig_pub"]),
            ik_dh_pub=b64d(data["ik_dh_pub"]),
            spk_pub=b64d(data["spk_pub"]),
            spk_sig=b64d(data["spk_sig"]),
        )

    # ------------------------------------------------------------------
    # Fase 5: directorio de contactos y verificación
    # ------------------------------------------------------------------
    def _check_identity_pinning(self, peer: str, peer_ik_dh_pub: bytes) -> None:
        """ Fase 5 / STRIDE (Suplantación):
                TOFU: fija la clave de identidad la primera vez que se ve.
                Si después cambia, alerta y revoca el estado VERIFICADO.
        """
        known_contacts = self.vault["known_contacts"]
        known = known_contacts.get(peer)
        peer_ik_b64 = b64e(peer_ik_dh_pub)
        local_ik_pub = b64d(self.vault["keys"]["ik_dh_pub"])
        safety_num = compute_safety_number(local_ik_pub, peer_ik_dh_pub)

        if known is None:
            known_contacts[peer] = peer_ik_b64
            print(f"\n[NUEVO CONTACTO] @{peer} añadido al directorio como [NO VERIFICADO].")
            print(f"  Safety Number: {safety_num}\n")
        elif known != peer_ik_b64:
            known_contacts[peer] = peer_ik_b64
            was_verified = peer in self.vault["verified_contacts"]
            if was_verified:
                self.vault["verified_contacts"].remove(peer)
            print("\n" + "!" * 60)
            print(f"ALERTA DE SEGURIDAD: La clave de identidad de '{peer}' CAMBIÓ.")
            print("Posible ataque de suplantación (MITM).")
            if was_verified:
                print("Se revocó su estado [VERIFICADO].")
            print(f"Nuevo Safety Number: {safety_num}")
            print("Vuelve a verificarlo en persona antes de confiar en este contacto.")
            print("!" * 60 + "\n")

    def is_verified(self, peer: str) -> bool:
        return peer in self.vault.get("verified_contacts", [])

    def badge(self, peer: str) -> str:
        return "[VERIFICADO]" if self.is_verified(peer) else "[NO VERIFICADO]"

    def set_verified(self, peer: str, verified: bool = True) -> None:
        if peer not in self.vault["known_contacts"]:
            raise ValueError(f"'{peer}' no está en tu directorio de contactos.")
        vlist = self.vault["verified_contacts"]
        if verified and peer not in vlist:
            vlist.append(peer)
        elif not verified and peer in vlist:
            vlist.remove(peer)
        self._save_state()

    def list_contacts(self) -> List[dict]:
        """Directorio local: usuario, estado de verificación y si hay sesión activa."""
        return [
            {
                "peer": peer,
                "verified": self.is_verified(peer),
                "has_session": peer in self.sessions,
            }
            for peer in sorted(self.vault["known_contacts"])
        ]

    def add_contact(self, peer: str) -> bool:
        """Descarga la identidad pública de un usuario y la fija en el directorio (TOFU)."""
        if peer == self.username:
            print("[INFO] No puedes añadirte a ti mismo como contacto.")
            return False
        if peer in self.vault["known_contacts"]:
            return True
        bundle = self._fetch_bundle(peer)
        if bundle is None:
            return False
        self._check_identity_pinning(peer, bundle.ik_dh_pub)
        self._save_state()
        return True

    def get_safety_number(self, peer: str) -> Optional[str]:
        """Safety Number con un contacto del directorio (lo añade si es nuevo)."""
        if not self.add_contact(peer):
            return None
        local_ik_pub = b64d(self.vault["keys"]["ik_dh_pub"])
        return compute_safety_number(local_ik_pub, b64d(self.vault["known_contacts"][peer]))

    def show_safety_number(self, peer: str) -> Optional[str]:
        """ Fase 5
                Muestra el Safety Number y su QR
                para verificación fuera de banda
        """
        sn = self.get_safety_number(peer)
        if sn is None:
            return None
        print(f"\nContacto      : @{peer} {self.badge(peer)}")
        print(f"Safety Number : {sn}\n")
        print_qr_console(build_qr_payload(self.username, peer, sn))
        return sn

    def verify_contact(self, peer: str, peer_code: str) -> bool:
        """
        Compara el Safety Number (o el contenido del QR) que muestra el contacto
        con el calculado localmente. Si coinciden, lo marca como VERIFICADO.
        """
        sn = self.get_safety_number(peer)
        if sn is None:
            return False

        code = peer_code.strip()
        if code.upper().startswith(QR_PREFIX):
            expected = build_qr_payload(self.username, peer, sn)
        else:
            code = code.replace(" ", "").upper()
            expected = sn.replace(" ", "")

        if hmac.compare_digest(code.encode(), expected.encode()):
            self.set_verified(peer, True)
            return True
        return False

    # ------------------------------------------------------------------
    # Fases 3 y 4: mensajería
    # ------------------------------------------------------------------
    def send_message(self, recipient: str, text: str) -> None:
        """ Fases 3 y 4:
                    Establece X3DH si es necesario,
                    avanza ratchet y envía cifrado
        """

        if recipient not in self.sessions:
            bundle = self._fetch_bundle(recipient)
            if bundle is None:
                return
            self._check_identity_pinning(recipient, bundle.ik_dh_pub)

            local_ik_priv = x25519.X25519PrivateKey.from_private_bytes(
                b64d(self.vault["keys"]["ik_dh_priv"])
            )
            local_ik_pub = b64d(self.vault["keys"]["ik_dh_pub"])

            self.sessions[recipient] = ChatSession.initiate_x3dh(
                local_ik_priv, local_ik_pub, bundle
            )

        packet = self.sessions[recipient].encrypt_message(text)
        payload = {
            "recipient": recipient,
            "sender_ik_dh": b64e(packet.sender_ik_dh),
            "ephemeral_pub": b64e(packet.ephemeral_pub),
            "counter": packet.counter,
            "nonce": b64e(packet.nonce),
            "ciphertext": b64e(packet.ciphertext),
        }

        res = httpx.post(
            f"{SERVER_URL}/messages", json=payload, headers=self._auth_headers(), **_http_kwargs()
        )
        if res.status_code == 201:
            self.vault["history"].append(
                {"dir": "OUT", "peer": recipient, "text": text, "ts": _now()}
            )
            self._save_state()
            print(f"[ENVIADO a @{recipient} {self.badge(recipient)} | n={packet.counter}]")
            if not self.is_verified(recipient):
                print("  Aviso: contacto sin verificar. Compara el Safety Number en el directorio [3].")
        else:
            print(f"[ERROR al enviar]: {res.text}")

    def check_inbox(self) -> List[dict]:
        """ Descarga mensajes del buzón,
            completa X3DH si es sesión nueva y descifra
        """

        res = httpx.get(f"{SERVER_URL}/messages", headers=self._auth_headers(), **_http_kwargs())
        if res.status_code != 200:
            print(f"[ERROR al consultar buzón]: {res.text}")
            return []

        messages = res.json()
        if not messages:
            print("[BUZÓN] No hay mensajes nuevos.")
            return []

        local_ik_priv = x25519.X25519PrivateKey.from_private_bytes(
            b64d(self.vault["keys"]["ik_dh_priv"])
        )
        local_ik_pub = b64d(self.vault["keys"]["ik_dh_pub"])
        local_spk_priv = x25519.X25519PrivateKey.from_private_bytes(
            b64d(self.vault["keys"]["spk_priv"])
        )

        received = []
        for msg in messages:
            sender = msg["sender"]
            sender_ik_dh = b64d(msg["sender_ik_dh"])
            ephemeral_pub = b64d(msg["ephemeral_pub"])

            # Sesion nueva: se crea de forma provisional y solo se guarda (junto con la
            # identidad del contacto) si el primer mensaje descifra correctamente.
            # Asi un paquete falso no deja una sesion inservible ni fija una clave falsa.
            is_new_session = sender not in self.sessions
            if is_new_session:
                session = ChatSession.accept_x3dh(
                    local_ik_priv, local_ik_pub, local_spk_priv, sender_ik_dh, ephemeral_pub
                )
            else:
                session = self.sessions[sender]

            packet = EncryptedPacket(
                sender_ik_dh=sender_ik_dh,
                ephemeral_pub=ephemeral_pub,
                counter=msg["counter"],
                nonce=b64d(msg["nonce"]),
                ciphertext=b64d(msg["ciphertext"]),
            )

            # Prueba: Intenta abrir el mensaje, si el paquete
            # estaba alterado o es falso, no se guarda 
            # la sesión ni la identidad del contacto.
            try:
                plaintext = session.decrypt_message(packet)
            except Exception as exc:
                reason = str(exc) or "etiqueta GCM inválida (paquete alterado o falso)"
                print(f"\n[RECHAZADO de @{sender}]: {type(exc).__name__}: {reason}")
                continue

            # Si logro tener exito el primer mensaje, 
            # fija la identidad del contacto y guarda la sesión
            if is_new_session:
                self._check_identity_pinning(sender, sender_ik_dh)
                self.sessions[sender] = session

            record = {"dir": "IN", "peer": sender, "text": plaintext, "ts": _now()}
            self.vault["history"].append(record)
            received.append(record)
            print(f"\n[{record['ts']}] @{sender} {self.badge(sender)} | n={packet.counter}: {plaintext}")

        self._save_state()
        return received

    def get_history(self, peer: str = "") -> List[dict]:
        return [h for h in self.vault["history"] if not peer or h["peer"] == peer]


# ----------------------------------------------------------------------
# Interfaz de consola
# ----------------------------------------------------------------------
def _contacts_menu(client: SecureClient) -> None:
    while True:
        contacts = client.list_contacts()
        print("\n--- DIRECTORIO DE CONTACTOS ---")
        if not contacts:
            print("(Aún no tienes contactos. Añade uno con la opción [a])")
        for c in contacts:
            status = "[VERIFICADO]   " if c["verified"] else "[NO VERIFICADO]"
            session = "sesión activa" if c["has_session"] else "sin sesión"
            print(f"  • @{c['peer']:<15} {status}  ({session})")

        print("\n[a] Añadir contacto  [s] Safety Number + QR  [v] Verificar contacto")
        print("[r] Quitar verificación  [Enter] Volver")
        opt = input("> ").strip().lower()

        if not opt:
            return
        if opt not in ("a", "s", "v", "r"):
            print("Opción inválida.")
            continue

        peer = input("Usuario: ").strip()
        if not peer:
            continue

        if opt == "a":
            if client.add_contact(peer):
                print(f"[OK] @{peer} está en tu directorio {client.badge(peer)}.")

        elif opt == "s":
            client.show_safety_number(peer)

        elif opt == "v":
            sn = client.show_safety_number(peer)
            if sn is None:
                continue
            print("\nCompara este código con el que ve tu contacto en SU pantalla (en persona o")
            print("por un canal de confianza). Pega aquí su Safety Number o el texto de su QR,")
            print("o escribe 's' si ya los comparaste visualmente y coinciden.")
            code = input("Código del contacto: ").strip()
            if code.lower() == "s":
                client.set_verified(peer, True)
                print(f"[OK] @{peer} marcado como [VERIFICADO].")
            elif client.verify_contact(peer, code):
                print(f"[OK] Los códigos coinciden. @{peer} marcado como [VERIFICADO].")
            else:
                print("[ALERTA] Los códigos NO coinciden. Posible MITM: el contacto sigue [NO VERIFICADO].")

        elif opt == "r":
            try:
                client.set_verified(peer, False)
                print(f"[OK] @{peer} marcado como [NO VERIFICADO].")
            except ValueError as exc:
                print(f"[ERROR] {exc}")


def _history_menu(client: SecureClient) -> None:
    peer = input("Filtrar por usuario (Enter para ver todo): ").strip()
    print("\n--- HISTORIAL LOCAL (bóveda cifrada) ---")
    history = client.get_history(peer)
    if not history:
        print("(Sin mensajes registrados)")
    for h in history:
        ts = h.get("ts", "----------  --:--:--")  # Mensajes de bóvedas antiguas sin fecha
        mark = "✓" if client.is_verified(h["peer"]) else "⚠"
        if h["dir"] == "OUT":
            print(f"[{ts}] Tú -> @{h['peer']} ({mark}): {h['text']}")
        else:
            print(f"[{ts}] @{h['peer']} ({mark}) -> Tú: {h['text']}")


def main() -> None:
    print("=== Mensajería Segura E2EE (Protocolo Signal Simplificado) ===")
    action = input("1) Registrarse  |  2) Iniciar sesión: ").strip()
    username = input("Usuario: ").strip()
    password = getpass.getpass("Contraseña: ")

    client = SecureClient(username, password)
    try:
        if action == "1":
            client.register()
            client.login()
        elif action == "2":
            client.login()
        else:
            print("Opción inválida.")
            return
    except Exception as exc:
        print(f"[FALLO]: {exc}")
        return

    while True:
        print("\n--- MENÚ PRINCIPAL ---")
        print("[1] Enviar mensaje cifrado")
        print("[2] Revisar buzón")
        print("[3] Directorio de contactos (Safety Number / QR / verificación)")
        print("[4] Historial de conversaciones")
        print("[5] Salir")
        cmd = input("> ").strip()

        try:
            if cmd == "1":
                dest = input("Destinatario: ").strip()
                msg = input("Mensaje: ")
                client.send_message(dest, msg)
            elif cmd == "2":
                client.check_inbox()
            elif cmd == "3":
                _contacts_menu(client)
            elif cmd == "4":
                _history_menu(client)
            elif cmd == "5":
                print("Bóveda cifrada guardada. Saliendo...")
                break
            else:
                print("Opción inválida.")
        except Exception as exc:
            print(f"[ERROR] {exc}")


if __name__ == "__main__":
    main()
