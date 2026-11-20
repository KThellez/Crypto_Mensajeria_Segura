import os

import pytest
from cryptography.exceptions import InvalidTag

from client.crypto_utils import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
    sign_prekey,
)
from client.session import MAX_SKIP, ChatSession, EncryptedPacket, PreKeyBundle


def _setup_users():
    # Identidad de Alicia Keys
    _, alice_ik_dh_priv = None, None
    alice_ik_dh_priv, alice_ik_dh_pub = generate_x25519_keypair()

    # Identidad y PreKey Bundle de Bob Stoloff
    bob_ik_sig_priv, bob_ik_sig_pub = generate_ed25519_keypair()
    bob_ik_dh_priv, bob_ik_dh_pub = generate_x25519_keypair()
    bob_spk_priv, bob_spk_pub = generate_x25519_keypair()
    bob_spk_sig = sign_prekey(bob_ik_sig_priv, bob_spk_pub)

    bob_bundle = PreKeyBundle(
        ik_sig_pub=bob_ik_sig_pub,
        ik_dh_pub=bob_ik_dh_pub,
        spk_pub=bob_spk_pub,
        spk_sig=bob_spk_sig,
    )
    return (alice_ik_dh_priv, alice_ik_dh_pub), (bob_ik_dh_priv, bob_ik_dh_pub, bob_spk_priv, bob_bundle)


def test_x3dh_and_ratchet_flow():
    (alice_priv, alice_pub), (bob_priv, bob_pub, bob_spk_priv, bob_bundle) = _setup_users()

    # Alicia inicia sesión y cifra dos mensajes
    alice_session = ChatSession.initiate_x3dh(alice_priv, alice_pub, bob_bundle)
    pkt0 = alice_session.encrypt_message("Hola Bob, primer mensaje")
    pkt1 = alice_session.encrypt_message("Segundo mensaje con clave nueva")

    # Bob acepta sesión usando los datos públicos del primer paquete
    bob_session = ChatSession.accept_x3dh(
        bob_priv, bob_pub, bob_spk_priv, pkt0.sender_ik_dh, pkt0.ephemeral_pub
    )

    assert bob_session.decrypt_message(pkt0) == "Hola Bob, primer mensaje"
    assert bob_session.decrypt_message(pkt1) == "Segundo mensaje con clave nueva"


def test_mitm_forged_prekey_rejected():
    (alice_priv, alice_pub), (_, _, _, bob_bundle) = _setup_users()

    # El servidor malicioso reemplaza la SPK de Bob por una propia
    _, attacker_spk_pub = generate_x25519_keypair()
    bob_bundle.spk_pub = attacker_spk_pub

    with pytest.raises(ValueError, match="ALERTA DE SEGURIDAD: La firma de Signed PreKey invalida MITM"):
        ChatSession.initiate_x3dh(alice_priv, alice_pub, bob_bundle)


def test_replay_attack_rejected():
    (alice_priv, alice_pub), (bob_priv, bob_pub, bob_spk_priv, bob_bundle) = _setup_users()

    alice_session = ChatSession.initiate_x3dh(alice_priv, alice_pub, bob_bundle)
    pkt0 = alice_session.encrypt_message("Transferir 100")

    bob_session = ChatSession.accept_x3dh(
        bob_priv, bob_pub, bob_spk_priv, pkt0.sender_ik_dh, pkt0.ephemeral_pub
    )
    assert bob_session.decrypt_message(pkt0) == "Transferir 100"

    # Un atacante captura pkt0 y lo reenvía por segunda vez
    with pytest.raises(ValueError, match="Mensaje repetido"):
        bob_session.decrypt_message(pkt0)


def _open_session():
    """Alicia inicia sesión, envía pkt0 y Bob lo descifra."""
    (alice_priv, alice_pub), (bob_priv, bob_pub, bob_spk_priv, bob_bundle) = _setup_users()
    alice = ChatSession.initiate_x3dh(alice_priv, alice_pub, bob_bundle)
    pkt0 = alice.encrypt_message("hola 0")
    bob = ChatSession.accept_x3dh(bob_priv, bob_pub, bob_spk_priv, pkt0.sender_ik_dh, pkt0.ephemeral_pub)
    assert bob.decrypt_message(pkt0) == "hola 0"
    return alice, bob, pkt0


def _forged(pkt: EncryptedPacket, counter: int) -> EncryptedPacket:
    """Paquete inyectado por un atacante de red: contador elegido y contenido aleatorio."""
    return EncryptedPacket(pkt.sender_ik_dh, pkt.ephemeral_pub, counter, os.urandom(12), os.urandom(40))


def test_tampered_ciphertext_rejected():
    alice, bob, _ = _open_session()
    pkt = alice.encrypt_message("Pagar 50 a Bob")
    tampered = EncryptedPacket(
        pkt.sender_ik_dh, pkt.ephemeral_pub, pkt.counter, pkt.nonce,
        pkt.ciphertext[:-1] + bytes([pkt.ciphertext[-1] ^ 0x01]),
    )
    with pytest.raises(InvalidTag):
        bob.decrypt_message(tampered)
    # El original sigue siendo aceptado: el intento fallido no alteró la sesión
    assert bob.decrypt_message(pkt) == "Pagar 50 a Bob"


def test_forged_packet_does_not_desync_session():
    alice, bob, pkt0 = _open_session()
    state_before = (bob.chain_key, bob.send_counter, set(bob.received_counters))

    with pytest.raises(InvalidTag):
        bob.decrypt_message(_forged(pkt0, counter=5))

    assert (bob.chain_key, bob.send_counter, bob.received_counters) == state_before
    assert bob.decrypt_message(alice.encrypt_message("hola 1")) == "hola 1"


def test_counter_beyond_max_skip_rejected_without_work():
    alice, bob, pkt0 = _open_session()
    chain_before = bob.chain_key

    with pytest.raises(ValueError, match="demasiado adelantado"):
        bob.decrypt_message(_forged(pkt0, counter=10**9))

    assert bob.chain_key == chain_before
    assert bob.decrypt_message(alice.encrypt_message("sigo vivo")) == "sigo vivo"


def test_lost_messages_are_skipped_up_to_max_skip():
    alice, bob, _ = _open_session()
    for _ in range(3):
        alice.encrypt_message("perdido en la red")
    assert bob.decrypt_message(alice.encrypt_message("llega")) == "llega"

    for _ in range(MAX_SKIP):
        alice.encrypt_message("perdido")
    assert bob.decrypt_message(alice.encrypt_message("en el límite")) == "en el límite"
