import httpx2
import pytest

from fastapi.testclient import TestClient

from client.cli import SecureClient
from client.crypto_utils import compute_safety_number
from server import database
from server.main import app

@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """ Aisla la base de datos SQLite, 
        las bovedas JSON y redirige httpx2 al servidor en memoria
    """
    
    monkeypatch.chdir(tmp_path)
    test_db = tmp_path / "test_e2e.db"
    monkeypatch.setattr(database, "DB_PATH", test_db)
    database.init_db()

    api_client = TestClient(app)
    monkeypatch.setattr(httpx2, "post", api_client.post)
    monkeypatch.setattr(httpx2, "get", api_client.get)


def test_full_end_to_end_chat(capsys):
    # Registro y login de Bob y Alicia (crea bob_vault.json y alicia_vault.json)
    bob = SecureClient("bob", "ClaveBob2026!")
    bob.register()
    bob.login()

    alicia = SecureClient("alicia", "ClaveAlicia2026!")
    alicia.register()
    alicia.login()

    # Alicia envía un mensaje cifrado a Bob (ejecuta X3DH + Ratchet)
    alicia.send_message("bob", "Hola Bob, este mensaje viaja cifrado E2EE")

    # Bob revisa su buzón y descifra el mensaje
    alicia_ik = alicia.vault["keys"]["ik_dh_pub"]
    bob_ik = bob.vault["keys"]["ik_dh_pub"]
    bob.check_inbox()

    salida = capsys.readouterr().out
    assert "Hola Bob, este mensaje viaja cifrado E2EE" in salida

    # Ambos clientes calculan exactamente el mismo Safety Number
    from client.cli import b64d
    assert compute_safety_number(b64d(alicia_ik), b64d(bob_ik)) == compute_safety_number(
        b64d(bob_ik), b64d(alicia_ik)
    )