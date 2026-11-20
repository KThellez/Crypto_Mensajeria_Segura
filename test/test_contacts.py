import os

import httpx
import pytest

from fastapi.testclient import TestClient

from client.cli import SecureClient, b64e, build_qr_payload
from client.crypto_utils import generate_x25519_keypair
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

    # Simula que el servidor entrega una clave de identidad distinta para bob (MITM)
    _, fake_ik = generate_x25519_keypair()
    alicia._check_identity_pinning("bob", fake_ik)

    assert not alicia.is_verified("bob")
    assert alicia.vault["known_contacts"]["bob"] == b64e(fake_ik)
    assert "CAMBIÓ" in capsys.readouterr().out


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
