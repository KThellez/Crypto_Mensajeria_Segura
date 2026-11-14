import pytest
from fastapi.testclient import TestClient

from server import database
from server.main import app


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Usa una base de datos SQLite temporal limpia para cada test."""
    test_db_file = tmp_path / "test_mensajeria.db"
    monkeypatch.setattr(database, "DB_PATH", test_db_file)
    database.init_db()


def test_register_login_and_mailbox_flow():
    with TestClient(app) as client:
        # Registrar a Bob stoloff y a Alicia keys
        res_bob = client.post("/register", json={
            "username": "bob",
            "password": "ClaveSuperSeguraBob123!",
            "ik_sig_pub": "bob_ik_sig_b64",
            "ik_dh_pub": "bob_ik_dh_b64",
            "spk_pub": "bob_spk_b64",
            "spk_sig": "bob_sig_b64",
        })
        assert res_bob.status_code == 201

        client.post("/register", json={
            "username": "alicia",
            "password": "ClaveSuperSeguraAlicia123!",
            "ik_sig_pub": "ali_ik_sig_b64",
            "ik_dh_pub": "ali_ik_dh_b64",
            "spk_pub": "ali_spk_b64",
            "spk_sig": "ali_sig_b64",
        })

        # Login de Alicia
        login_ali = client.post("/login", json={
            "username": "alicia",
            "password": "ClaveSuperSeguraAlicia123!",
        })
        assert login_ali.status_code == 200
        token_ali = login_ali.json()["access_token"]
        headers_ali = {"Authorization": f"Bearer {token_ali}"}

        # Alicia pide el bundle de Bob
        bundle_res = client.get("/keys/bob", headers=headers_ali)
        assert bundle_res.status_code == 200
        assert bundle_res.json()["spk_pub"] == "bob_spk_b64"

        # Alicia envía un paquete cifrado al buzón de Bob
        send_res = client.post("/messages", headers=headers_ali, json={
            "recipient": "bob",
            "sender_ik_dh": "ali_ik_dh_b64",
            "ephemeral_pub": "ek_ali_b64",
            "counter": 0,
            "nonce": "nonce_b64",
            "ciphertext": "texto_cifrado_incomprensible_b64",
        })
        assert send_res.status_code == 201

        # Bob inicia sesión y recoge sus mensajes
        login_bob = client.post("/login", json={
            "username": "bob",
            "password": "ClaveSuperSeguraBob123!",
        })
        headers_bob = {"Authorization": f"Bearer {login_bob.json()['access_token']}"}

        inbox = client.get("/messages", headers=headers_bob)
        assert inbox.status_code == 200
        mensajes = inbox.json()
        assert len(mensajes) == 1
        assert mensajes[0]["sender"] == "alicia"
        assert mensajes[0]["ciphertext"] == "texto_cifrado_incomprensible_b64"

        # Verificar que el buzón quedó vacío tras la entrega
        inbox_second = client.get("/messages", headers=headers_bob)
        assert inbox_second.json() == []


def test_unauthorized_access_rejected():
    with TestClient(app) as client:
        res = client.get("/messages", headers={"Authorization": "Bearer token_falso_123"})
        assert res.status_code == 401