import os

import httpx
import pytest

from fastapi.testclient import TestClient

from client.cli import SecureClient, b64d, b64e, build_qr_payload
from client.crypto_utils import generate_ed25519_keypair, generate_x25519_keypair, sign_prekey
from server import database
from server.main import app


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Aísla BD, bóvedas y redirige httpx al servidor en memoria."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test_contacts.db")
    database.init_db()

    api_client = TestClient(app)
    monkeypatch.setattr(httpx, "post", api_client.post)
    monkeypatch.setattr(httpx, "get", api_client.get)


@pytest.fixture
def alicia_bob():
    bob = SecureClient("bob", "ClaveBob2026!")
    bob.register()
    bob.login()
    alicia = SecureClient("alicia", "ClaveAlicia2026!")
    alicia.register()
    alicia.login()
    return alicia, bob


def test_new_contact_starts_unverified(alicia_bob):
    alicia, _ = alicia_bob
    assert alicia.add_contact("bob")
    assert alicia.list_contacts() == [{"peer": "bob", "verified": False, "has_session": False}]


def test_unknown_user_is_not_added(alicia_bob):
    alicia, _ = alicia_bob
    assert not alicia.add_contact("eva")
    assert alicia.list_contacts() == []


def test_verify_with_matching_safety_number_and_qr(alicia_bob):
    alicia, bob = alicia_bob
    sn_bob = bob.get_safety_number("alicia")

    # Safety Number tecleado con espacios / minúsculas
    assert alicia.verify_contact("bob", sn_bob.lower())
    assert alicia.is_verified("bob")

    # El QR es idéntico en ambos extremos
    qr_bob = build_qr_payload("bob", "alicia", sn_bob)
    assert bob.verify_contact("alicia", qr_bob)


def test_verify_rejects_wrong_code(alicia_bob):
    alicia, _ = alicia_bob
    assert not alicia.verify_contact("bob", "00000 00000 00000")
    assert not alicia.is_verified("bob")


def test_verification_persists_in_vault(alicia_bob):
    alicia, bob = alicia_bob
    alicia.verify_contact("bob", bob.get_safety_number("alicia"))

    reopened = SecureClient("alicia", "ClaveAlicia2026!")
    reopened.login()
    assert reopened.is_verified("bob")


def test_identity_change_revokes_verification(alicia_bob, capsys):
    alicia, bob = alicia_bob
    alicia.verify_contact("bob", bob.get_safety_number("alicia"))

    # Simula que el servidor entrega una clave X25519 de identidad distinta para bob (MITM)
    real_sig = b64d(bob.vault["keys"]["ik_sig_pub"])
    _, fake_ik = generate_x25519_keypair()
    alicia._check_identity_pinning("bob", real_sig, fake_ik)

    assert not alicia.is_verified("bob")
    assert alicia.vault["known_contacts"]["bob"]["ik_dh_pub"] == b64e(fake_ik)
    assert "CAMBIÓ (acuerdo X25519)" in capsys.readouterr().out


def _substitute_signing_key(username: str) -> None:
    """
    Servidor malicioso: sustituye IK_sig de un usuario y publica una SPK propia
    firmada con ella. La firma es válida, IK_dh no cambia.
    """
    attacker_sig_priv, attacker_sig_pub = generate_ed25519_keypair()
    _, attacker_spk_pub = generate_x25519_keypair()
    with database.get_connection() as conn:
        conn.execute(
            "UPDATE users SET ik_sig_pub = ?, spk_pub = ?, spk_sig = ? WHERE username = ?",
            (
                b64e(attacker_sig_pub),
                b64e(attacker_spk_pub),
                b64e(sign_prekey(attacker_sig_priv, attacker_spk_pub)),
                username,
            ),
        )
        conn.commit()


def test_safety_number_covers_signing_key(alicia_bob):
    alicia, bob = alicia_bob
    # Antes de cualquier contacto, el servidor sustituye la clave de firma de bob
    _substitute_signing_key("bob")

    # La firma de la SPK es "válida" y IK_dh es el real, pero el Safety Number
    # que ve alicia ya no coincide con el que ve bob: la verificación lo detecta
    assert alicia.get_safety_number("bob") != bob.get_safety_number("alicia")
    assert not alicia.verify_contact("bob", bob.get_safety_number("alicia"))


def test_signing_key_substitution_alerts_known_contact(alicia_bob, capsys):
    alicia, bob = alicia_bob
    alicia.verify_contact("bob", bob.get_safety_number("alicia"))
    capsys.readouterr()

    _substitute_signing_key("bob")
    alicia.send_message("bob", "hola")  # Nueva sesión: descarga el bundle sustituido

    assert "CAMBIÓ (firma Ed25519)" in capsys.readouterr().out
    assert not alicia.is_verified("bob")


def test_receiver_pins_sender_signing_key(alicia_bob):
    alicia, bob = alicia_bob
    alicia.send_message("bob", "hola")
    bob.check_inbox()

    assert bob.vault["known_contacts"]["alicia"] == {
        "ik_sig_pub": alicia.vault["keys"]["ik_sig_pub"],
        "ik_dh_pub": alicia.vault["keys"]["ik_dh_pub"],
    }
    assert bob.get_safety_number("alicia") == alicia.get_safety_number("bob")


def test_receiver_rejects_incoherent_directory_identity(alicia_bob, capsys):
    alicia, bob = alicia_bob
    alicia.send_message("bob", "hola")

    # El directorio publica para alicia una IK_dh distinta a la usada en el mensaje
    _, other_ik = generate_x25519_keypair()
    with database.get_connection() as conn:
        conn.execute("UPDATE users SET ik_dh_pub = ? WHERE username = 'alicia'", (b64e(other_ik),))
        conn.commit()

    assert bob.check_inbox() == []
    assert "alicia" not in bob.sessions
    assert "alicia" not in bob.vault["known_contacts"]
    assert "Posible MITM" in capsys.readouterr().out


def test_legacy_vault_contacts_are_migrated(alicia_bob, capsys):
    alicia, bob = alicia_bob
    # Bóveda con el formato antiguo: {usuario: ik_dh_pub_b64} y bob verificado
    alicia.vault["known_contacts"] = {"bob": bob.vault["keys"]["ik_dh_pub"]}
    alicia.vault["verified_contacts"] = ["bob"]
    alicia._save_state()

    reopened = SecureClient("alicia", "ClaveAlicia2026!")
    reopened.login()

    assert reopened.vault["known_contacts"]["bob"]["ik_sig_pub"] is None
    assert not reopened.is_verified("bob")
    assert "Vuelve a verificar a: @bob" in capsys.readouterr().out

    # Al consultar el Safety Number se completa la clave de firma sin alerta
    assert reopened.get_safety_number("bob") == bob.get_safety_number("alicia")
    assert reopened.vault["known_contacts"]["bob"]["ik_sig_pub"] == bob.vault["keys"]["ik_sig_pub"]
    assert "CAMBIÓ" not in capsys.readouterr().out


def test_history_records_timestamp_and_filter(alicia_bob):
    alicia, bob = alicia_bob
    alicia.send_message("bob", "Hola Bob")
    received = bob.check_inbox()

    assert [m["text"] for m in received] == ["Hola Bob"]
    assert bob.get_history("alicia")[0]["ts"]
    assert bob.get_history("eva") == []


def test_forged_first_packet_does_not_create_session_or_pin(alicia_bob):
    alicia, bob = alicia_bob

    # Un atacante deposita en el buzón de Bob un primer paquete falso "de alicia"
    httpx.post("/messages", headers=alicia._auth_headers(), json={
        "recipient": "bob",
        "sender_ik_dh": b64e(generate_x25519_keypair()[1]),
        "ephemeral_pub": b64e(generate_x25519_keypair()[1]),
        "counter": 0,
        "nonce": b64e(os.urandom(12)),
        "ciphertext": b64e(os.urandom(40)),
    })
    assert bob.check_inbox() == []
    assert "alicia" not in bob.sessions
    assert "alicia" not in bob.vault["known_contacts"]

    # El primer mensaje legítimo sigue funcionando
    alicia.send_message("bob", "Hola de verdad")
    assert [m["text"] for m in bob.check_inbox()] == ["Hola de verdad"]
