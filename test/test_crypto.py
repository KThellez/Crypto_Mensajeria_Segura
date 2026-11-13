# TESTs CRYPTO UTILS

from client.crypto_utils import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
    sign_prekey,
    verify_prekey_signature,
    compute_hmac_sha256    
)


def test_sign_and_verify_prekey():
    priv_sig, pub_sig =  generate_ed25519_keypair()
    _, pub_spk = generate_x25519_keypair()
    
    sig = sign_prekey(priv_sig, pub_spk)
    
    assert verify_prekey_signature(pub_sig, pub_spk, sig) is True
    assert verify_prekey_signature(pub_sig, pub_spk, b'x' * 64 ) is False
    

def test_symetric_ratchet_hmac():
    chain_key = b'\x01' * 32
    msg_key = compute_hmac_sha256(chain_key, b'\x01')
    next_ck = compute_hmac_sha256(chain_key, b'\x02')
    
    assert len(msg_key) == 32
    assert msg_key != next_ck