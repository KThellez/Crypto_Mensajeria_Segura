#Establecimiento de sesion (X3DH)

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

@dataclass
class PreKeyBundle:
    """ Paquete publico de un usuario descargado
        desde el directorio del servidor
    """
    ik_sig_pub: bytes   #32B Ed25519
    ik_dh_pub: bytes    #32B X25519
    spk_pub: bytes      #32B X25519
    spk_sig: bytes      #64B Firma Ed25519 sobre el spk_pub

@dataclass
class EncryptedPacket:
    """Estructura enviada al buzon del servidor"""
    sender_ik_dh: bytes
    ephemeral_pub: bytes #Necesaria en el primer mensaje para que el receptor complete el X3DH
    counter: int
    nonce: bytes
    ciphertext: bytes
    
    
@dataclass
class ChatSession:
    """ Gestiona el estado criptografico (X3DH + Ratchet)
        entre el usuario local y un par
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
        Fase 3 (El Emisor): Verifica la SPK del receptor, calcula el DH1 | DH2 | DH3 
                            y deriva RK
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
        Fase 3 (Receptor): Repite los 3 calculos DH usando sus claves para
                            obtener la misma clave raiz RK
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
        """ Construye 
                AD = IK_Emisor 
                IK_receptor
                n (entero de 8 bytes big-endian)
        """
        return sender_ik + receiver_ik + struct.pack(">Q", counter)
    
    def _step_ratchet(self) -> Tuple[bytes, int]:
        """
        Fase 4 
                Deriva Mk_n = HMAC(CK_n,0x01)
                Avanza CK_{n+1} = HMAC(CK_n, 0x02)
        """
        msg_key = compute_hmac_sha256(self.chain_key, b"\x01")
        self.chain_key = compute_hmac_sha256(self.chain_key, b"\02")
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
        """
        
        # Mitigacion Stride (Manipulacion / Replay): rechazar contadores repetidos o pasados
        if packet.counter in self.received_counters or packet.counter < self.send_counter:
            raise ValueError(f"ALERTA DE SEGURIDAD: Mensaje repetido o fuera de orden (n={packet.counter})")
        
        #Avanzar la cadena si algun mensaje previo se perdio en red hasta llegar a packet.counter
        while self.send_counter < packet.counter:
            _, _ = self._step_ratchet()
            self.send_counter += 1
            
        msg_key, _ = self._step_ratchet()
        self.send_counter +=1
        
        # Construir el mismo AD esperado (emisor -> receptor local -> contador)
        ad = self._build_associated_data(self.peer_ik_dh_pub, self.local_ik_dh_pub, packet.counter)
        
        
        try:
            plaintext_bytes = decrypt_aes_gcm(msg_key, packet.nonce, packet.ciphertext, associated_data=ad)
        finally:
            # Garantiza borrar el MK_n si el decifrado falla por mainipulacion
            del msg_key
            
        self.received_counters.add(packet.counter)
        return plaintext_bytes.decode("utf-8")        