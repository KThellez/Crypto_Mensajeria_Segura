import base64
import getpass
import os

from typing import Dict

import httpx

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


from client.crypto_utils import(
    compute_safety_number,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    load_encrypted_vault,
    save_encrypted_vault,
    sign_prekey,
)
from client.session import ChatSession, EncryptedPacket, PreKeyBundle

SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:8000")

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))

def priv_to_b64(priv_key) -> str:
    raw = priv_key.private_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PrivateFormat.Raw,
        encryption_algorithm = serialization.NoEncryption(),
    )
    return b64e(raw)


class SecureClient:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.vault_path = f"{username}_vault.json"
        self.token: str = ""
        self.vault: Dict = {}
        self.sessions: Dict[str, ChatSession] = {} 
        
    def _save_state(self) -> None:
        """ Guarda claves privadas, contactos conocidos, 
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

        res = httpx.post(f"{SERVER_URL}/register", json=payload)
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
            "known_contacts": {},
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

        res = httpx.post(
            f"{SERVER_URL}/login",
            json={"username": self.username, "password": self.password},
        )
        if res.status_code != 200:
            raise RuntimeError(f"Error de autenticación en servidor: {res.text}")

        self.token = res.json()["access_token"]
        self._restore_sessions()
        print(f"[OK] Sesión iniciada como '{self.username}'. Token válido por 1 hora.")

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def _check_identity_pinning(self, peer: str, peer_ik_dh_pub: bytes) -> None:
        """ Fase 5 / STRIDE:
                    Alerta si la clave de identidad de 
                    un contacto conocido cambió
        """
        
        known = self.vault["known_contacts"].get(peer)
        peer_ik_b64 = b64e(peer_ik_dh_pub)
        local_ik_pub = b64d(self.vault["keys"]["ik_dh_pub"])
        safety_num = compute_safety_number(local_ik_pub, peer_ik_dh_pub)

        if known is None:
            self.vault["known_contacts"][peer] = peer_ik_b64
            print(f"\n[NUEVO CONTACTO] Safety Number con {peer}:\n  {safety_num}\n")
        elif known != peer_ik_b64:
            print("\n" + "!" * 60)
            print(f"ALERTA DE SEGURIDAD: La clave de identidad de '{peer}' CAMBIÓ.")
            print("Posible ataque de suplantación (MITM). Contacto NO verificado.")
            print(f"Nuevo Safety Number: {safety_num}")
            print("!" * 60 + "\n")

    def send_message(self, recipient: str, text: str) -> None:
        """ Fases 3 y 4: 
                    Establece X3DH si es necesario, 
                    avanza ratchet y envía cifrado
        """
        
        if recipient not in self.sessions:
            res = httpx.get(f"{SERVER_URL}/keys/{recipient}", headers=self._auth_headers())
            if res.status_code != 200:
                print(f"[ERROR] No se pudo obtener el bundle de '{recipient}': {res.text}")
                return

            data = res.json()
            bundle = PreKeyBundle(
                ik_sig_pub=b64d(data["ik_sig_pub"]),
                ik_dh_pub=b64d(data["ik_dh_pub"]),
                spk_pub=b64d(data["spk_pub"]),
                spk_sig=b64d(data["spk_sig"]),
            )
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

        res = httpx.post(f"{SERVER_URL}/messages", json=payload, headers=self._auth_headers())
        if res.status_code == 201:
            self.vault["history"].append({"dir": "OUT", "peer": recipient, "text": text})
            self._save_state()
            print(f"[ENVIADO a {recipient} | n={packet.counter}]")
        else:
            print(f"[ERROR al enviar]: {res.text}")
            
    def check_inbox(self) -> None:
        """ Descarga mensajes del buzón, 
            completa X3DH si es sesión nueva y descifra
        """
        
        res = httpx.get(f"{SERVER_URL}/messages", headers=self._auth_headers())
        if res.status_code != 200:
            print(f"[ERROR al consultar buzón]: {res.text}")
            return

        messages = res.json()
        if not messages:
            print("[BUZÓN] No hay mensajes nuevos.")
            return

        local_ik_priv = x25519.X25519PrivateKey.from_private_bytes(
            b64d(self.vault["keys"]["ik_dh_priv"])
        )
        local_ik_pub = b64d(self.vault["keys"]["ik_dh_pub"])
        local_spk_priv = x25519.X25519PrivateKey.from_private_bytes(
            b64d(self.vault["keys"]["spk_priv"])
        )

        for msg in messages:
            sender = msg["sender"]
            sender_ik_dh = b64d(msg["sender_ik_dh"])
            ephemeral_pub = b64d(msg["ephemeral_pub"])

            if sender not in self.sessions:
                self._check_identity_pinning(sender, sender_ik_dh)
                self.sessions[sender] = ChatSession.accept_x3dh(
                    local_ik_priv, local_ik_pub, local_spk_priv, sender_ik_dh, ephemeral_pub
                )

            packet = EncryptedPacket(
                sender_ik_dh=sender_ik_dh,
                ephemeral_pub=ephemeral_pub,
                counter=msg["counter"],
                nonce=b64d(msg["nonce"]),
                ciphertext=b64d(msg["ciphertext"]),
            )

            try:
                plaintext = self.sessions[sender].decrypt_message(packet)
                print(f"\n[{sender} | n={packet.counter}]: {plaintext}")
                self.vault["history"].append({"dir": "IN", "peer": sender, "text": plaintext})
            except Exception as exc:
                print(f"\n[RECHAZADO de {sender}]: {exc}")

        self._save_state()
        
    def show_safety_number(self, peer: str) -> None:
        """ Fase 5
                Muestra el Safety Number actual 
                con un contacto para verificación manual
        """
        
        peer_ik_b64 = self.vault["known_contacts"].get(peer)
        if not peer_ik_b64:
            print(f"[INFO] Aún no has intercambiado claves con '{peer}'.")
            return
        local_ik_pub = b64d(self.vault["keys"]["ik_dh_pub"])
        sn = compute_safety_number(local_ik_pub, b64d(peer_ik_b64))
        print(f"[SAFETY NUMBER con {peer}]: {sn}")
        

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
        print("\nComandos: [1] Enviar mensaje  [2] Revisar buzón  [3] Ver Safety Number  [4] Salir")
        cmd = input("> ").strip()
        if cmd == "1":
            dest = input("Destinatario: ").strip()
            msg = input("Mensaje: ")
            client.send_message(dest, msg)
        elif cmd == "2":
            client.check_inbox()
        elif cmd == "3":
            peer = input("Contacto: ").strip()
            client.show_safety_number(peer)
        elif cmd == "4":
            break


if __name__ == "__main__":
    main()   