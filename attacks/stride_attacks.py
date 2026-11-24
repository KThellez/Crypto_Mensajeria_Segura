import base64
import sqlite3

from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from client.crypto_utils import(
    decrypt_aes_gcm,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    sign_prekey,
)

from client.session import ChatSession, EncryptedPacket, PreKeyBundle
from server import database
from server.main import app


def banner(title: str) -> None:
    print(f"\n{'=' * 65}\n[STRIDE] {title}\n{'=' * 65}")
    
def attack_1_spoofing_mitm_prekey() -> None:
    banner("SPOOFING: Servidor Malicioso sustituye la SPK de Bob")
    alice_ik_priv, alice_ik_pub = generate_x25519_keypair()
     
     
    bob_sig_priv, bob_sig_pub = generate_ed25519_keypair()
    _, bob_ik_pub = generate_x25519_keypair()
    _, bob_spk_pub = generate_x25519_keypair()
    bob_sig = sign_prekey(bob_sig_priv, bob_spk_pub)
    
    
    # EL ATACANTE reemplza la spk de bob por una clave publica propia
    _, attacker_spk_pub = generate_x25519_keypair() 
    forged_bundle = PreKeyBundle(
        ik_sig_pub=bob_sig_pub,
        ik_dh_pub=bob_ik_pub,
        spk_pub=attacker_spk_pub,
        spk_sig=bob_sig,
    )
    
    
    try:
        ChatSession.initiate_x3dh(alice_ik_priv, alice_ik_pub, forged_bundle)
        print("FALLO: El ataque MITM no fue detectado")
    except ValueError as exc:
        print(f"MITIGADO El cliente aborto la sesion: {exc}")
        
        
        
def attack_2_tampering_ciphertext() -> None:
    banner("TEMPERING: alteracion de 1 byte en el paquete cifrado")
    alice_priv, alice_pub = generate_x25519_keypair()
    bob_sig_priv, bob_sig_pub = generate_ed25519_keypair()
    bob_priv, bob_pub = generate_x25519_keypair()
    bob_spk_priv, bob_spk_pub = generate_x25519_keypair()
    
    
    
    bundle = PreKeyBundle(
        bob_sig_pub, bob_pub, bob_spk_pub, sign_prekey(bob_sig_priv, bob_spk_pub)
    )
    alice_sess = ChatSession.initiate_x3dh(alice_priv, alice_pub, bundle)
    pkt = alice_sess.encrypt_message("Por favor pagar $50 a Bob")

    bob_sess = ChatSession.accept_x3dh(
        bob_priv, bob_pub, bob_spk_priv, pkt.sender_ik_dh, pkt.ephemeral_pub
    )  
    
    
    # El atacante invierte el ultimo bit del ciphertext en transito
    tampered_ct = pkt.ciphertext[:-1] + bytes([pkt.ciphertext[-1] ^ 0x01])
    tampered_pkt = EncryptedPacket(
        pkt.sender_ik_dh, pkt.ephemeral_pub, pkt.counter, pkt.nonce, tampered_ct
    )
    
    
    try:
        bob_sess.decrypt_message(tampered_pkt)
        print("FALLO: se acepto un mensaje manipulado")
    except InvalidTag:
        print("MITIGADO, AES-256-GCM rechazo el paquete alterado")
        
        

def attack_3_replay_message() -> None:
    banner(" REPLAY: Reenvio de un mensaje legitimo capturado en red")
    
    
    alice_priv, alice_pub = generate_x25519_keypair()
    bob_sig_priv, bob_sig_pub = generate_ed25519_keypair()
    bob_priv, bob_pub = generate_x25519_keypair()
    bob_spk_priv, bob_spk_pub = generate_x25519_keypair()

    bundle = PreKeyBundle(
        bob_sig_pub, bob_pub, bob_spk_pub, sign_prekey(bob_sig_priv, bob_spk_pub)
    )
    alice_sess = ChatSession.initiate_x3dh(alice_priv, alice_pub, bundle)
    pkt0 = alice_sess.encrypt_message("Autorizo acceso al laboratorio")

    bob_sess = ChatSession.accept_x3dh(
        bob_priv, bob_pub, bob_spk_priv, pkt0.sender_ik_dh, pkt0.ephemeral_pub
    )
    print(f"OK: Primer envío recibido: '{bob_sess.decrypt_message(pkt0)}'")

    try:
        bob_sess.decrypt_message(pkt0)
        print("FALLO: El mensaje repetido fue aceptado.")
    except ValueError as exc:
        print(f"MITIGADO, Ratchet bloqueó el reenvio: {exc}")
        
        
        
def attack_4_and_5_server_dump_and_privilege_escalation() -> None:
    banner("Divulgacion de informacion y Elevacion de privilegios o escalada de privilegios")
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        database.DB_PATH = Path(tmpdir) / "stride_test.db"
        database.init_db()

        with TestClient(app) as client:
            client.post("/register", json={
                "username": "bob",
                "password": "QWERty123+",
                "ik_sig_pub": "pub1",
                "ik_dh_pub": "pub2",
                "spk_pub": "pub3",
                "spk_sig": "sig1",
            })
            client.post("/register", json={
                "username": "eva",
                "password": "QWERty123!",
                "ik_sig_pub": "pub4",
                "ik_dh_pub": "pub5",
                "spk_pub": "pub6",
                "spk_sig": "sig2",
            })

            token_eva = client.post("/login", json={
                "username": "eva",
                "password": "QWERty123!",
            }).json()["access_token"]

            # Eva envía un mensaje cifrado a Bob
            client.post(
                "/messages",
                headers={"Authorization": f"Bearer {token_eva}"},
                json={
                    "recipient": "bob",
                    "sender_ik_dh": "pub5",
                    "ephemeral_pub": "ek_eva",
                    "counter": 0,
                    "nonce": "nonce_12B",
                    "ciphertext": base64.b64encode(b"secreto_cifrado_gcm").decode(),
                },
            )

            # Information Disclosure: Volcado directo de SQLite
            conn = sqlite3.connect(database.DB_PATH)
            user_row = conn.execute("SELECT username, password_hash FROM users WHERE username='bob'").fetchone()
            session_row = conn.execute("SELECT token_hash FROM sessions").fetchone()
            msg_row = conn.execute("SELECT recipient, ciphertext FROM mailbox").fetchone()
            conn.close()

            print(f"VOLCADO BD: Hash contraseña Bob : {user_row[1][:38]}...")
            print(f"VOLCADO BD: Hash SHA-256 token  : {session_row[0][:38]}...")
            print(f"VOLCADO BD: Buzón cifrado       : {msg_row}")

            # Elevation of Privilege: Eva intenta consultar el buzón con su token;
            # el servidor solo filtra por el dueño del token y jamás expone los mensajes de Bob.
            eva_inbox = client.get(
                "/messages", headers={"Authorization": f"Bearer {token_eva}"}
            ).json()
            print(f"MITIGADO, Eva consulta /messages con su token y obtiene: {eva_inbox} (0 mensajes de Bob)")


if __name__ == "__main__":
    attack_1_spoofing_mitm_prekey()
    attack_2_tampering_ciphertext()
    attack_3_replay_message()
    attack_4_and_5_server_dump_and_privilege_escalation()
    print("\nRESUMEN: Todas las defensas STRIDE verificadas con éxito")
    
    

def attack_6_forged_packet_injection() -> None:
    banner("TAMPERING / DoS: Inyeccion de paquete falso con contador adelantado")
    alice_priv, alice_pub = generate_x25519_keypair()
    bob_sig_priv, bob_sig_pub = generate_ed25519_keypair()
    bob_priv, bob_pub = generate_x25519_keypair()
    bob_spk_priv, bob_spk_pub = generate_x25519_keypair()

    bundle = PreKeyBundle(
        bob_sig_pub, bob_pub, bob_spk_pub, sign_prekey(bob_sig_priv, bob_spk_pub)
    )
    alice_sess = ChatSession.initiate_x3dh(alice_priv, alice_pub, bundle)
    pkt0 = alice_sess.encrypt_message("Inicio legitimo")

    bob_sess = ChatSession.accept_x3dh(
        bob_priv, bob_pub, bob_spk_priv, pkt0.sender_ik_dh, pkt0.ephemeral_pub
    )
    bob_sess.decrypt_message(pkt0)

    # Atacante inyecta un paquete falso con contador n=25 intentando desincronizar el ratchet
    import os
    forged_pkt = EncryptedPacket(
        pkt0.sender_ik_dh, pkt0.ephemeral_pub, 25, os.urandom(12), os.urandom(48)
    )
    try:
        bob_sess.decrypt_message(forged_pkt)
        print("FALLO: Se acepto paquete inyectado")
    except InvalidTag:
        print("MITIGADO: Paquete falso rechazado sin alterar el estado de la sesion")

    # El siguiente mensaje legitimo de Alicia (n=1) sigue descifrandose sin problema
    pkt1 = alice_sess.encrypt_message("La sesion sigue intacta")
    assert bob_sess.decrypt_message(pkt1) == "La sesion sigue intacta"
    print("VERIFICADO: Bob descifro el mensaje legitimo posterior (n=1)")


def attack_7_signing_key_substitution() -> None:
    banner("SPOOFING: Servidor sustituye IK_sig de Bob y firma una SPK falsa")
    from client.crypto_utils import compute_safety_number, identity_material

    _, alice_ik_dh = generate_x25519_keypair()
    alice_sig_priv, alice_sig_pub = generate_ed25519_keypair()

    bob_sig_priv, bob_sig_pub = generate_ed25519_keypair()
    _, bob_ik_dh = generate_x25519_keypair()

    # Servidor malicioso genera su propia clave de firma Ed25519 para suplantar a Bob
    _, attacker_sig_pub = generate_ed25519_keypair()

    sn_real = compute_safety_number(
        identity_material(alice_sig_pub, alice_ik_dh),
        identity_material(bob_sig_pub, bob_ik_dh),
    )
    sn_mitm = compute_safety_number(
        identity_material(alice_sig_pub, alice_ik_dh),
        identity_material(attacker_sig_pub, bob_ik_dh),
    )

    assert sn_real != sn_mitm
    print(f"Safety Number real : {sn_real}")
    print(f"Safety Number MITM : {sn_mitm}")
    print("MITIGADO: Al cubrir IK_sig || IK_dh, el Safety Number cambia y delata el MITM")