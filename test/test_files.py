import httpx2
import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from client.cli import SecureClient
from client.crypto_utils import decrypt_file_envelope, encrypt_file_envelope
from server import database
from server.main import app


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test_files.db")
    database.init_db()

    api_client = TestClient(app)
    monkeypatch.setattr(httpx2, "post", api_client.post)
    monkeypatch.setattr(httpx2, "get", api_client.get)


def test_encrypted_file_attachment_e2e(tmp_path):
    bob = SecureClient("bob", "ClaveBob2026!")
    bob.register()
    bob.login()

    alicia = SecureClient("alicia", "ClaveAlicia2026!")
    alicia.register()
    alicia.login()

    secret_doc = tmp_path / "contrato_confidencial.txt"
    secret_doc.write_bytes(b"Contenido binario ultra secreto 2026")

    alicia.send_file("bob", str(secret_doc))
    received = bob.check_inbox()

    assert len(received) == 1
    assert "contrato_confidencial.txt" in received[0]["text"]
    downloaded = tmp_path / "downloads_bob" / "contrato_confidencial.txt"
    assert downloaded.read_bytes() == b"Contenido binario ultra secreto 2026"


def test_tampered_file_envelope_rejected(tmp_path):
    doc = tmp_path / "evidencia.bin"
    doc.write_bytes(b"Datos originales integros")

    envelope_str = encrypt_file_envelope(str(doc))
    # Alterar un carácter dentro del ciphertext en Base64
    corrupted = envelope_str[:-5] + ("A" if envelope_str[-5] != "A" else "B") + envelope_str[-4:]

    with pytest.raises((InvalidTag, ValueError)):
        decrypt_file_envelope(corrupted, output_dir=str(tmp_path / "out"))