"""pyca/cryptography calls whose verdicts differ. Not a real service."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def demo(key: bytes) -> list[object]:
    ecb = Cipher(algorithms.AES(key), modes.ECB())
    md5 = hashes.Hash(hashes.MD5())
    sha1 = hashes.Hash(hashes.SHA1())
    triple_des = Cipher(algorithms.TripleDES(key[:24]), modes.CBC(b"\x00" * 8))
    weak_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    signer = ed25519.Ed25519PrivateKey.generate()
    exchange = x25519.X25519PrivateKey.generate()
    return [ecb, md5, sha1, triple_des, weak_rsa, signer, exchange]
