import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "mensajeria.bd"

def get_connection() -> sqlite3.Connection:
    """ Se abre una conexion a SQLite con 
        acceso a columnas por nombre
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """ Crea las tablas de usuarios (claves públicas),  
        sesiones y buzón cifrado.
    """
    with get_connection() as conn:
        # Tabla de usuarios: solo 
        #       hash Argon2id y bundle público (nunca claves privadas)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                ik_sig_pub TEXT NOT NULL,
                ik_dh_pub TEXT NOT NULL,
                spk_pub TEXT NOT NULL,
                spk_sig TEXT NOT NULL
            )
        """)

        # Tabla de sesiones: solo guarda el 
        # SHA-256 del token y su timestamp de expiración
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at REAL NOT NULL,
                FOREIGN KEY (username) REFERENCES users(username)
            )
        """)

        # Buzón de mensajes pendientes: 
        #       solo texto cifrado y metadatos públicos de X3DH
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mailbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                sender TEXT NOT NULL,
                sender_ik_dh TEXT NOT NULL,
                ephemeral_pub TEXT NOT NULL,
                counter INTEGER NOT NULL,
                nonce TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                FOREIGN KEY (recipient) REFERENCES users(username)
            )
        """)
        conn.commit()