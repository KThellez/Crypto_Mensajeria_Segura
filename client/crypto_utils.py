# Archivo ToolBox criptografico del lado del cliente
#Primitivas de cryptography y argon2-cffi

#Importaciones generales
import os
import json
import base64
import hashlib
from typing import Tuple

#Importaciones de las librerias argon2 y cryptography
from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# GENERACION Y SERIALIZACION DE CLAVES ASIMETRICAS
def generate_ed25519_keypair() -> Tuple[ed25519 .Ed25519PrivateKey, bytes]:
    """Genera un par de Ed25519 (Firma de identidad) 
        y retorna (privada, publica_raw_32B)
    """
    priv = ed25519.Ed25519PrivateKey.generate()     # Generacion clave privada
    pub_bytes = priv.public_key().public_bytes(     # generacion de Bytes publicos
        encoding = serialization.Encoding.Raw,      
        format = serialization.PublicFormat.Raw
    )
    return priv, pub_bytes      # Retornamos nuestra clave privada y los bytes publicos


def generate_x25519_keypair() -> Tuple[x25519 .X25519PrivateKey, bytes]:
    """Genera un par de x25519 (acuerdo de claves DelfiHellman) 
        y retorna (privada, publica_raw_32B)
    """
    priv = x25519.X25519PrivateKey.generate()       # Generamos la clave privada 
    pub_bytes = priv.public_key().public_bytes(     # generacion de Bytes publicos
        encoding = serialization.Encoding.Raw,
        format = serialization.PublicFormat.Raw
    )
    return priv, pub_bytes      # Retornamos nuestra clave privada y los bytes publics

# Ya con lo anterior logramos tener la identidad dual ED25519 + X25519 

def sign_prekey(ik_sig_priv: ed25519.Ed25519PrivateKey, spk_pub_bytes: bytes) -> bytes:
    """ Firma la clave publica Signed Prekey (SPL) con la clave privada
        de identidad Ed25519
    """
    return ik_sig_priv.sign(spk_pub_bytes)

def verify_prekey_signature(ik_sig_pub_bytes: bytes, spk_pub_bytes: bytes , signature: bytes) -> bool:
    """ Verifica que la SPK fue firmada legitimamente por
        el dueño de IK_sig (Identity Key Signature).
        Recibe la clave PUBLICA Ed25519 del dueño (nunca la privada).
    """
    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(ik_sig_pub_bytes)
        pub_key.verify(signature, spk_pub_bytes)
        return True
    except InvalidSignature:
        return False
    

# ACUERDO DIFFIEHELLMAN Y DERIVACION DE CLAVES
def compute_dh(priv_key: x25519.X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
    """Ejecuta el intercambio de x25519 y
        devuelve 32 bytes de secreto compartido
    """
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return priv_key.exchange(peer_pub)

def derive_hkdf(
    secret_material: bytes, 
    info: bytes, 
    salt: bytes = None, 
    length: int = 32
    ) -> bytes:
    """ Deriva claves criptograficas de
        longitud fija usando HKDF-SHA256 con contexto (info)
    """
    hkdf = HKDF(
        algorithm = hashes.SHA256(),
        length = length,
        salt = salt,
        info = info,
    )
    return hkdf.derive(secret_material)

def compute_hmac_sha256(key: bytes, data: bytes) -> bytes:
    """ Calcula el HMAC-SHA256 (usando en el ratchet simetrico
        con constantes 0x01 y 0x02)
        Esto sucede dentro de la sesion activa del chat,
        generando claves efimeras para cada chat individual
        
        Nuetras constantes 0x01 y 0x02 son las etiquetas de separacion de dominio:
        0x01 deriva la clave de mensaje, cifrar/decifrar el mensaje actual
        0x02 deriva la siguiente clave encadenada (avanza el estadode la cadena sin poder retroseder el mismo)        
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


# CIFRADO AUTENTICO con (AES-256-GCM)

def encrypt_aes_gcm(
    key: bytes, 
    plaintext: bytes, 
    associated_data: bytes = b"" 
    ) -> Tuple[bytes, bytes]:
    """ Cifra con AES-256-GCM (clave 32B, nonce aleatorio de 12B y tag de 16B)
        Retorna (nonce, ciphertext_con_tag  
    """
    if len(key) != 32:
        raise ValueError("AES-256-GMC reqyuere una clave exacta de 32 bytes")
    nonce  = os.urandom(12) #96 bits
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce , ciphertext

def decrypt_aes_gcm(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes = b""
    ) -> bytes:
    """ Decifrea y verifica la integridad con aES-256-GCM
        Lanza un InvalidTag si el mensaje o los datos asociados fueron alterados/manipulados
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM, requiere una clave exacta de 32 bytes")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

# VERIFICACIOND E IDENTIDAD
def identity_material(ik_sig_pub: bytes, ik_dh_pub: bytes) -> bytes:
    """ Identidad criptografica completa de un usuario: IK_sig (Ed25519) || IK_dh (X25519).
        Ambas claves deben entrar en el Safety Number: si solo entrara IK_dh, el servidor
        podria sustituir IK_sig (y firmar una SPK propia) sin que el numero cambiara.
    """
    return ik_sig_pub + ik_dh_pub


def compute_safety_number(identity_a: bytes, identity_b: bytes) -> str:
    """ Calcula el Safety Number = SHA-256(ID_menor || ID_mayor)
        donde ID = identity_material(IK_sig, IK_dh) de cada usuario,
        formateandolo en bloques legibles.
        Ordenamos ambas identidades para que A y B obtengan exactamente
        el mismo numero
    """

    ordered = sorted([identity_a, identity_b])
    digest = hashlib.sha256(ordered[0] + ordered[1]).hexdigest()
    #agruamos los primeros 60 caracteres hex en 12 bloques de 5
    #para una lectura mas comoda en la consola
    blocks = [digest[i:i+5].upper() for i in range(0, 60, 5)]
    return " ".join(blocks)


#  ALMACENAMIENTO LOCAL DEL CIFRADO con (argon2ID + AES-256-GCM)
def derive_storage_key(password: str, salt: bytes) -> bytes:
    """ Deriva la clave de 32 bytes desde la contraseña local usando Argon2id:
            64 MiB (65536 KiB), 3 iteraciones, 4 hilos
    """
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    
def save_encrypted_vault(filepath: str, password: str, data: dict) -> None:
    """ Cifra un diccionario (claves privadas/historial) en 
        disco con sal e IV unjicos 
    """
    salt = os.urandom(16) # sal de 16bytes
    key = derive_storage_key(password, salt)
    plaintext = json.dumps(data).encode("utf-8")
    nonce, ciphertext, = encrypt_aes_gcm(key, plaintext)
    
    vault_payload = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(vault_payload, f, indent=2)
        
        
def load_encrypted_vault(filepath: str, password: str) -> dict:
    """ Descifra la boveda local
        Falla con un invalidtag si el password es incorrecto 
    """
    with open(filepath, "r", encoding="utf-8") as f:
        vault_payload = json.load(f)
        
    salt = base64.b64decode(vault_payload["salt"])
    nonce = base64.b64decode(vault_payload["nonce"])
    ciphertext = base64.b64decode(vault_payload["ciphertext"])
    
    key = derive_storage_key(password, salt)
    plaintext = decrypt_aes_gcm(key, nonce, ciphertext)
    return json.loads(plaintext.decode("utf-8"))
    
    
    
    
# Cifrado de sobre para archivos con (Envelope encryption)

FILE_ENVELOPE_PREFIX = "__E2EE_FILE__:"


def encrypt_file_envelope(filepath: str) -> str:
    """
    Implementa Envelope Encryption para un archivo local:
      1. Genera una DEK (Data Encryption Key) aleatoria de 256 bits.
      2. Calcula el SHA-256 del archivo en claro para verificación E2E.
      3. Cifra el contenido binario con AES-256-GCM usando el nombre como AD.
      4. Empaqueta la DEK y el criptograma en un sobre JSON listo para el Ratchet.
    """
    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        raw_data = f.read()

    file_hash = hashlib.sha256(raw_data).hexdigest()
    dek = os.urandom(32)  # Clave de datos de un solo uso (256 bits)
    nonce, ciphertext = encrypt_aes_gcm(
        dek, raw_data, associated_data=filename.encode("utf-8")
    )

    envelope = {
        "filename": filename,
        "size": len(raw_data),
        "sha256": file_hash,
        "dek": base64.b64encode(dek).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    del dek
    return FILE_ENVELOPE_PREFIX + json.dumps(envelope)


def decrypt_file_envelope(payload_text: str, output_dir: str) -> dict:
    """
    Abre un sobre de archivo recibido por el Ratchet, descifra el binario con la DEK,
    verifica la integridad SHA-256 y lo guarda sanitizando la ruta (anti Path Traversal).
    """
    if not payload_text.startswith(FILE_ENVELOPE_PREFIX):
        raise ValueError("El mensaje no contiene un sobre de archivo válido.")

    envelope = json.loads(payload_text[len(FILE_ENVELOPE_PREFIX):])
    # Sanitiza el nombre para evitar ataques de Path Traversal (ej. ../../archivo)
    safe_name = os.path.basename(envelope["filename"]) or "archivo_recibido.bin"

    dek = base64.b64decode(envelope["dek"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])

    try:
        raw_data = decrypt_aes_gcm(
            dek, nonce, ciphertext, associated_data=safe_name.encode("utf-8")
        )
    finally:
        del dek

    actual_hash = hashlib.sha256(raw_data).hexdigest()
    if not hmac.compare_digest(actual_hash, envelope["sha256"]):
        raise ValueError("ALERTA DE INTEGRIDAD: El SHA-256 del archivo descifrado no coincide.")

    os.makedirs(output_dir, exist_ok=True)
    saved_path = os.path.join(output_dir, safe_name)
    with open(saved_path, "wb") as f:
        f.write(raw_data)

    return {
        "filename": safe_name,
        "size": len(raw_data),
        "sha256": actual_hash,
        "saved_path": saved_path,
    }