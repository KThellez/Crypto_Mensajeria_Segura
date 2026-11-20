"""
    Modúlo Client/Session.py
    Gestiona el estado criptografico de la sesion de chat entre dos pares
    usando el protocolo X3DH + Ratchet.

    Mapa de flujo de la sesion:
        1. PreKeyBundle: Tarjeta de presentacion publica que se descarga del servidor.
        2. initiate_x3dh: Emisor que verifica la firma Ed25519, calcula DH1, DH2 , DH3, deriva RK y borra el EK.
        3. Receptor replica los mismos 3 productos DH, usando su SPK privada.
        4. Avanza el ratchet(HMAC), vincula identidades en AD y borra el MK_n despues de cifrar/descifrar.  

"""
import struct
from dataclasses import dataclass, field
from typing import Set, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519

from client.crypto_utils import (
    compute_dh,
    compute_hmac_sha256,
    decrypt_aes_gcm,
    derive_hkdf,
    encrypt_aes_gcm,
    generate_x25519_keypair,
    verify_prekey_signature,
)

HKDF_INFO_X3DH = b"UDFJC_Crypto_X3DH_RootKey_v1"

# Maximo de mensajes perdidos que el receptor acepta saltar en un solo paso
# (mismo concepto que MAX_SKIP en la especificacion del Double Ratchet de Signal)
MAX_SKIP = 1000

@dataclass
class PreKeyBundle:
    """ Paquete publico de un usuario descargado
        desde el directorio del servidor

        Claves publicas de un destinatario obtenidas desde el servidor ciego
    """
    ik_sig_pub: bytes   # Clave publica Ed25519 (32B), para verificar autenticidad    
    ik_dh_pub: bytes    # Clave publica X25519 (32B), para el intercambio Diffie-Hellman (identidad a largo plazo)
    spk_pub: bytes      # Signed PreKey X25519 (32B), para el intercambio Diffie-Hellman (firmada por ik_sig_priv)
    spk_sig: bytes      # Firma Ed25519 (64B) permite probar que spk_pub pertenece al dueño (ik_sig_pub), evitando MITM

@dataclass
class EncryptedPacket:
    """ Estructura enviada al buzon del servidor
        Estructura del paquete cifrado que viaja por red y reposa en el buzon del servidor. 
        Contiene la informacion necesaria para que el receptor derive 
        la misma clave de cifrado y descifre el mensaje.
    """
    sender_ik_dh: bytes     # Identidad DH del emisor (Necesaria para calcular DH2 Y AD)
    ephemeral_pub: bytes    # Clave publica efimera EK_A (Necesaria en el primer mensaje para que el receptor complete el X3DH)
    counter: int            # Numero de secuencia del mensaje (anti-replay y orden de entrega)
    nonce: bytes            # Vector de inicializacion unico de 12 bytes (AES-GCM 96 bits)
    ciphertext: bytes       # Texto cifrado + Tag de autenticacion GCM de 16 bytes (AES-GCM 128 bits)   
    
@dataclass
class ChatSession:
    """ Gestiona el estado criptografico (X3DH + Ratchet)
        entre el usuario local y un par

        Mantiene el estado activo del ratchet para un par de usuarios.
    """
    local_ik_dh_pub: bytes
    peer_ik_dh_pub: bytes
    chain_key: bytes
    ephemeral_pub: bytes
    send_counter: int = 0
    received_counters: Set[int] = field(default_factory=set)
    
    
    @classmethod
    def initiate_x3dh(
        cls,
        local_ik_dh_priv: x25519.X25519PrivateKey,
        local_ik_dh_pub: bytes,
        peer_bundle: PreKeyBundle,
    ) -> "ChatSession":
        """
            Inicia una sesion X3DH (emisor)
            pasos:
                1. Verifica la firma ED25519 de la SPK del receptor. Si falla, aborta (detiene los MITM)
                2. Genera clave efimera x25519 (EK) exclusiva para esta sesion
                3. Calcula los 3 productos Diffie-Hellman (DH1, DH2, DH3)
                4. Deriva la clave raiz RK con HKDF-SHA256
                    4.1: DH1 = con X25519(IK_A_priv, SPK_B_pub) Autentica a Alicia ante bob
                    4.2: DH2 = con X25519(EK_A_priv, IK_B_pub) Autentica a Bob ante Alicia
                    4.3: DH3 = con X25519(EK_A_priv, SPK_B_pub) Aporta secreto efimero a la session (forward secrecy)
                5. Borra la clave efimera EK y los productos DH de memoria
        """
        
        #Mitigacion STRIDE (Suplantacion): aborta si la firma de la SPK no es valida
        if not verify_prekey_signature(
            peer_bundle.ik_sig_pub, 
            peer_bundle.spk_pub, 
            peer_bundle.spk_sig
            ):
            raise ValueError("ALERTA DE SEGURIDAD: La firma de Signed PreKey invalida MITM")
        
        # Generacion de la clave efimeroa EK
        # (se descartara su parte privada al salir de esta funcion)
        ek_priv, ek_pub = generate_x25519_keypair()
        
        
        # Tiple intercambio Diffie-Hellman (X3DH)
        dh1 = compute_dh(local_ik_dh_priv, peer_bundle.spk_pub)            
        dh2 = compute_dh(ek_priv, peer_bundle.ik_dh_pub)            
        dh3 = compute_dh(ek_priv, peer_bundle.spk_pub)            
        
        
        # Derivar la claver raiz RK con HKDF-SHA256
        root_key = derive_hkdf(dh1 + dh2 + dh3, info=HKDF_INFO_X3DH)
        
        
        # ek_priv, dh1, dh2, dh3
        # quedan fuera de alcance al ser capturados de memoria
        del ek_priv, dh1, dh2, dh3
        
        return cls(
            local_ik_dh_pub = local_ik_dh_pub,
            peer_ik_dh_pub = peer_bundle.ik_dh_pub,
            chain_key = root_key,
            ephemeral_pub = ek_pub,
        )
        
        
    @classmethod
    def accept_x3dh(
        cls,
        local_ik_dh_priv: x25519.X25519PrivateKey,
        local_ik_dh_pub: bytes,
        local_spk_priv: x25519.X25519PrivateKey,
        sender_ik_dh_pub: bytes,
        sender_ephemeral_pub: bytes,
    ) -> "ChatSession":
        """
            Acepta una sesión X3DH entrante (lado del receptor / Bob).
            Por la propiedad conmutativa de Diffie-Hellman (g^{ab} = g^{ba}), Bob obtiene
            exactamente los mismos bytes en DH1, DH2 y DH3 y deriva la misma clave raíz RK.
        """
        dh1 = compute_dh(local_spk_priv, sender_ik_dh_pub)
        dh2 = compute_dh(local_ik_dh_priv, sender_ephemeral_pub)
        dh3 = compute_dh(local_spk_priv, sender_ephemeral_pub)
        
        root_key = derive_hkdf(dh1 + dh2 + dh3, info=HKDF_INFO_X3DH)
        
         # dh1, dh2, dh3
                # quedan fuera de alcance al ser capturados de memoria
                
        return cls(
            local_ik_dh_pub = local_ik_dh_pub,
            peer_ik_dh_pub = sender_ik_dh_pub,
            chain_key = root_key,
            ephemeral_pub = sender_ephemeral_pub,
        )
        
    def _build_associated_data(
        self, 
        sender_ik: bytes, 
        receiver_ik: bytes, 
        counter:int,
        ) -> bytes:
        """ 
            Construye el contexto autenticado (AD = IK_emisor || IK_receptor || n (entero de 8 bytes big-endian)).
            Impide que un atacante reasigne un mensaje a otro destinatario o altere su secuencia.
        """
        return sender_ik + receiver_ik + struct.pack(">Q", counter)
    
    @staticmethod
    def _kdf_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
        """
            Toma la llave actual de la cadena (CK_n) y la pasa por una función de un solo 
            sentido (con ello un atacante ya no puede volver atras) usando dos constantes 
            distintas para obtener dos claves diferentes:
                MK_n     = HMAC-SHA256(CK_n, 0x01)  -> clave de este mensaje (se usa y se borra)
                CK_{n+1} = HMAC-SHA256(CK_n, 0x02)  -> siguiente clave de cadena (para el futuro)
        """
        msg_key = compute_hmac_sha256(chain_key, b"\x01")
        next_chain_key = compute_hmac_sha256(chain_key, b"\x02")
        return msg_key, next_chain_key

    def _step_ratchet(self) -> Tuple[bytes, int]:
        """
            Avanza el ratchet simétrico un paso (Forward Secrecy):
            deriva MK_n, reemplaza CK_n por CK_{n+1} y devuelve (MK_n, n).
            CK_n se sobrescribe, por lo que no se puede volver atrás.
        """
        msg_key, self.chain_key = self._kdf_chain(self.chain_key)
        return msg_key, self.send_counter
    
    def encrypt_message(self, plaintext: str) -> EncryptedPacket:
        """ Cifra un mensaje avanando el ratchet y destruyendo MK_n al terminar 
        """
        msg_key, counter = self._step_ratchet()
        self.send_counter += 1
        
        ad = self._build_associated_data(
            self.local_ik_dh_pub, 
            self.peer_ik_dh_pub, 
            counter
            )
        nonce, ciphertext = encrypt_aes_gcm(
            msg_key,
            plaintext.encode("utf-8"),
            associated_data = ad
        )
        
        
        # Forward secrecy: eliminando la clave de este mensaje
        del msg_key
        
        
        return EncryptedPacket(
            sender_ik_dh = self.local_ik_dh_pub,
            ephemeral_pub = self.ephemeral_pub,
            counter = counter,
            nonce = nonce,
            ciphertext = ciphertext
        )
        
        
    def decrypt_message(self, packet: EncryptedPacket) -> str:
        """ Verifica orden/anti-replay, avanza el rachet hasta el contador
            del paquete y descifra

            - Si el contador ya fue procesado -> Lanza ValueError (bloquea Replay).
            - Si el ciphertext o AD fueron modificados -> AES-GCM lanza InvalidTag (bloquea Tampering).
        """
        
        # Mitigacion Stride (Manipulacion / Replay): rechazar contadores repetidos o pasados
        if packet.counter in self.received_counters or packet.counter < self.send_counter:
            raise ValueError(f"ALERTA DE SEGURIDAD: Mensaje repetido o fuera de orden (n={packet.counter})")

        # Mitigacion (Denegacion de servicio): un contador enorme obligaria a calcular
        # millones de HMAC. Se limita cuantos mensajes perdidos se pueden saltar.
        skipped = packet.counter - self.send_counter
        if skipped > MAX_SKIP:
            raise ValueError(
                f"ALERTA DE SEGURIDAD: Contador demasiado adelantado (n={packet.counter}, "
                f"esperado <= {self.send_counter + MAX_SKIP})"
            )

        # El ratchet se avanza sobre una COPIA local de la cadena. El estado de la sesion
        # solo se modifica si la etiqueta GCM es valida: asi un paquete falso con un
        # contador alto no puede desincronizar la sesion (ver test_forged_packet_*).
        chain_key = self.chain_key
        for _ in range(skipped):        # Mensajes previos perdidos en la red
            _, chain_key = self._kdf_chain(chain_key)
        msg_key, next_chain_key = self._kdf_chain(chain_key)

        # Construir el mismo AD esperado (emisor -> receptor local -> contador)
        ad = self._build_associated_data(self.peer_ik_dh_pub, self.local_ik_dh_pub, packet.counter)

        try:
            plaintext_bytes = decrypt_aes_gcm(msg_key, packet.nonce, packet.ciphertext, associated_data=ad)
        finally:
            # Garantiza borrar el MK_n si el descifrado falla por manipulacion
            del msg_key

        # Descifrado autentico: ahora si se confirma el avance del ratchet
        self.chain_key = next_chain_key
        self.send_counter = packet.counter + 1
        self.received_counters.add(packet.counter)
        return plaintext_bytes.decode("utf-8")