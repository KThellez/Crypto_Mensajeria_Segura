"""
Módulo: server/main.py
Propósito: API REST en FastAPI que opera como directorio de claves públicas y buzón cifrado.

Principio arquitectónico (Zero-Knowledge / Servidor Ciego):
    - Este módulo NO importa client/crypto_utils.py ni client/session.py.
    - Nunca recibe contraseñas en claro en BD (usa Argon2id) ni claves privadas.
    - Los tokens de sesión de 256 bits se almacenan únicamente como su hash SHA-256.
    - Cada usuario solo puede leer y vaciar su propio buzón (mitiga Elevation of Privilege).
"""

import hashlib
import secrets
import sqlite3
import time

from contextlib import asynccontextmanager
from typing import List

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

from server.database import get_connection, init_db


#Configuracion para Argon2ID segun nuestro doc de diseño
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    salt_len=16,
)

TOKEN_TTL_SECONDS = 3600 #Expira en 1 hora

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Servidor Ciego E2EE - UDFJC", lifespan=lifespan)



# Modelos de datos (Esquemas JSON)
class RegisterRequest(BaseModel):
    username: str
    password: str
    ik_sig_pub: str
    ik_dh_pub: str
    spk_pub: str
    spk_sig: str

class LoginRequest(BaseModel):
    username: str
    password: str
    
class SendMessageRequest(BaseModel):
    recipient: str
    sender_ik_dh: str
    ephemeral_pub: str
    counter: int
    nonce: str
    ciphertext: str
    


# Utilidades de sesion y AUTORIZACION

def hash_token(token: str) -> str:
    """ Calcula el SHA-256 del token para no almacenar
        credenciales vivas en la BD
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def get_current_user(authorization: str = Header(...)) -> str:
    """
    Dependencia de seguridad Bearer.
    Verifica que el token exista en BD (comparando su SHA-256) y no haya expirado.
    Devuelve el username autenticado para aislar los buzones por propietario.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Formato de autorización inválido. Use 'Bearer <token>'.",
        )

    raw_token = authorization.removeprefix("Bearer ").strip()
    token_digest = hash_token(raw_token)

    with get_connection() as conn:
        row = conn.execute(
            "SELECT username, expires_at FROM sessions WHERE token_hash = ?",
            (token_digest,),
        ).fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido o inexistente.",
            )

        if time.time() > row["expires_at"]:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest,))
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="El token de sesión ha expirado.",
            )

        return row["username"]
    
    
# ENDPOINTS
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest):
    """
    Fase 1
        Registro usuario con hash Argon2ID
        y publica su Prekey bundle
    """
    pwd_hash = ph.hash(payload.password)
    
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, ik_sig_pub, ik_dh_pub, spk_pub, spk_sig)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.username,
                    pwd_hash,
                    payload.ik_sig_pub,
                    payload.ik_dh_pub,
                    payload.spk_pub,
                    payload.spk_sig,
                ),
            )
            conn.commit()
            
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El nombre de usuario ya está registrado.",
        )

    return {"message": f"Usuario '{payload.username}' registrado correctamente."}


@app.post("/login")
def login(payload: LoginRequest):
    """ Fase2
            Verifica la contraseña con Argon2ID
            y emite token de 256 bit (1hora)
    """
    with get_connection() as conn:
        user = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (payload.username,),
        ).fetchone()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales incorrectas.",
            )

        try:
            ph.verify(user["password_hash"], payload.password)
        except VerifyMismatchError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales incorrectas.",
            )
            
        #Genera 256 bit aleatorios (32 -> Base64 URL-safe)
        raw_token = secrets.token_urlsafe(32)
        token_digest = hash_token(raw_token) 
        expires_at = time.time() + TOKEN_TTL_SECONDS
        
        conn.execute(
            "INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)",
            (token_digest, payload.username, expires_at),
        )
        conn.commit()

    return {"access_token": raw_token, "token_type": "bearer", "expires_in": TOKEN_TTL_SECONDS}


@app.get("/keys/{target_username}")
def get_prekey_bundle(target_username: str, current_user: str = Depends(get_current_user)):
    """Fase 3
            Entrega el PreKey Bundle público 
            de un destinatario a un usuario autenticado
    """
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT username, ik_sig_pub, ik_dh_pub, spk_pub, spk_sig
            FROM users WHERE username = ?
            """,
            (target_username,),
        ).fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario destinatario no encontrado.",
        )

    return dict(row)


@app.post("/messages", status_code=status.HTTP_201_CREATED)
def send_message(payload: SendMessageRequest, current_user: str = Depends(get_current_user)):
    """ Fase 4 
            Deposita un paquete cifrado 
            en el buzón del destinatario
    """
    with get_connection() as conn:
        recipient_exists = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (payload.recipient,)
        ).fetchone()

        if not recipient_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="El destinatario no existe.",
            )

        conn.execute(
            """
            INSERT INTO mailbox (recipient, sender, sender_ik_dh, ephemeral_pub, counter, nonce, ciphertext)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.recipient,
                current_user,
                payload.sender_ik_dh,
                payload.ephemeral_pub,
                payload.counter,
                payload.nonce,
                payload.ciphertext,
            ),
        )
        conn.commit()

    return {"status": "Mensaje almacenado en el buzón cifrado"}

@app.get("/messages")
def fetch_messages(current_user: str = Depends(get_current_user)) -> List[dict]:
    """
        Entrega y vacía los mensajes pendientes exclusivamente del 
            usuario dueño del token
        Mitiga elevación de privilegios (STRIDE)
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, sender, sender_ik_dh, ephemeral_pub, counter, nonce, ciphertext
            FROM mailbox WHERE recipient = ? ORDER BY id ASC
            """,
            (current_user,),
        ).fetchall()

        messages = [dict(r) for r in rows]

        if messages:
            conn.execute("DELETE FROM mailbox WHERE recipient = ?", (current_user,))
            conn.commit()

    return messages