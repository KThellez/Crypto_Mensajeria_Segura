import pytest
from client.crypto_utils import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
    sign_prekey,
)
from client.session import ChatSession, PreKeyBundle


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