"""
    Modulo ui/app   
    Proposito: Capa de presentacion Web desacoplada en FastApi
    Mantiene claves privadas, el ratchet y la boveda cifrada 
    en el dispositivo del cliente.
"""

import base64
import os
import tempfile
import threading
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from client.cli import SecureClient, build_qr_payload

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Cliente Web E2EE - UDFJC")


# Se usa el candado para evitar condiciones de carrera
# entre el polling del buzon y el envio 
_lock = threading.Lock()
_active_client: Optional[SecureClient] = None


# Esquema de entrada, validacion de tipos y campos obligatorios

class AuthPayload(BaseModel):
    action: str # Register o Login
    username: str
    password: str

class MessagePayload(BaseModel):
    recipient: str
    text: str
    
class ContactPayload(BaseModel):
    peer: str
    
class VerifyPayload(BaseModel):
    peer: str
    code: str
    
class FileUploadPayload(BaseModel):
    recipient: str
    filename: str
    content_b64: str
    

def _require_client() -> SecureClient:
    if _active_client is None:
        raise HTTPException(
            status_code=401,
            detail="No hay sesion local activa."
            )
    return _active_client


# Rutas de interfaz y API local
@app.get("/", response_class=HTMLResponse)
def index():
    html_file = STATIC_DIR / "index.html"
    if not html_file.exists() or html_file.stat().st_size == 0:
        return HTMLResponse("<h2>Interfaz web</h2>")
    return HTMLResponse(html_file.read_text(encoding="utf-8"))


@app.post("/api/auth")
def authenticate(payload: AuthPayload):
    global _active_client
    username = payload.username.strip()
    if not username or not payload.password:
        raise HTTPException(
            status_code=400,
            detail="Usuario y contraseña obligatiors"
            )
    
    with _lock:
        candidate = SecureClient(username, payload.password)
        try:
            if payload.action == "register":
                candidate.register()
                if not os.path.exists(f"{username}_vault.json"):
                    raise HTTPException(
                        status_code=400,
                        detail="No se pudo registrar (verifica que el servidor :8000 esté activo o prueba otro usuario).",
                    )
            elif payload.action != "login":
                raise HTTPException(
                    status_code=400,
                    detail="Accion invalida",
                )
            candidate.login()
            _active_client = candidate
            return {
                "status": "ok",
                "username": candidate.username,
            }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            )


@app.post("/api/logout")
def logout():
    global _active_client
    with _lock:
        if _active_client is not None:
            _active_client._save_state()
            _active_client = None
    return {"status": "logged_out"}




@app.get("/api/state")
def get_state(peer: str = ""):
    client = _require_client()
    with _lock:
        try:
            client.check_inbox()
        except Exception:
            pass  # Si el servidor central no responde temporalmente, conserva estado local

        contacts = client.list_contacts()
        for c in contacts:
            sn = client.get_safety_number(c["peer"])
            c["safety_number"] = sn
            c["qr_payload"] = build_qr_payload(client.username, c["peer"], sn) if sn else ""

        return {
            "username": client.username,
            "contacts": contacts,
            "history": client.get_history(peer),
        }
        
        
@app.post("/api/messages")
def send_message(payload: MessagePayload):
    client = _require_client()
    with _lock:
        try:
            client.send_message(payload.recipient.strip(), payload.text)
            return {"status": "sent"}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/files")
def send_file(payload: FileUploadPayload):
    client = _require_client()
    safe_name = os.path.basename(payload.filename) or "adjunto.bin"
    with _lock:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / safe_name
            tmp_file.write_bytes(base64.b64decode(payload.content_b64))
            try:
                client.send_file(payload.recipient.strip(), str(tmp_file))
                return {"status": "sent", "filename": safe_name}
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            
@app.get("/api/downloads/{filename}")
def download_received_file(filename: str):
    client = _require_client()
    safe_name = os.path.basename(filename)
    file_path = Path(f"downloads_{client.username}") / safe_name
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado en descargas locales.")
    return FileResponse(path=file_path, filename=safe_name)


@app.post("/api/contacts")
def add_contact(payload: ContactPayload):
    client = _require_client()
    peer = payload.peer.strip()
    with _lock:
        if not client.add_contact(peer):
            raise HTTPException(status_code=404, detail=f"No se pudo añadir a '{peer}'.")
        sn = client.get_safety_number(peer)
        return {
            "peer": peer,
            "verified": client.is_verified(peer),
            "safety_number": sn,
            "qr_payload": build_qr_payload(client.username, peer, sn) if sn else "",
        }


@app.post("/api/contacts/verify")
def verify_contact(payload: VerifyPayload):
    client = _require_client()
    peer = payload.peer.strip()
    with _lock:
        if payload.code.strip().lower() == "manual":
            client.set_verified(peer, True)
            return {"verified": True}
        ok = client.verify_contact(peer, payload.code)
        if not ok:
            raise HTTPException(status_code=400, detail="El código no coincide. Posible MITM.")
        return {"verified": True}


if __name__ == "__main__":
    host = os.getenv("WEB_UI_HOST", "127.0.0.1")
    port = int(os.getenv("WEB_UI_PORT", "8080"))
    uvicorn.run("ui.app:app", host=host, port=port, reload=False)