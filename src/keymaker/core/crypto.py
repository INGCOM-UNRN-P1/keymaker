"""Motor de criptografía simétrica autenticada y firmas asimétricas de Keymaker."""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


def derivar_clave_pbkdf2(passphrase: str, salt: bytes, length: int = 32, iterations: int = 600_000) -> bytes:
    """Deriva una clave simétrica robusta a partir de una frase de paso usando PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def derivar_clave_hkdf(master_key: bytes, context: str, salt: Optional[bytes] = None, length: int = 32) -> bytes:
    """Deriva una subclave criptográfica usando HKDF-SHA256 con contexto (ej: legajo o padrón de estudiante)."""
    salt_bytes = salt if salt is not None else b"\x00" * 32
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt_bytes,
        info=context.encode("utf-8"),
    )
    return hkdf.derive(master_key)


def calcular_sha256(data: bytes) -> str:
    """Calcula el digest SHA-256 en formato hexadecimal."""
    return hashlib.sha256(data).hexdigest()


def calcular_sha256_archivo(ruta_archivo: str) -> str:
    """Calcula el digest SHA-256 de un archivo en disco."""
    h = hashlib.sha256()
    with open(ruta_archivo, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def cifrar_aes_gcm(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Cifra datos con AES-256-GCM.
    Retorna (nonce, ciphertext_con_tag).
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requiere una clave de 32 bytes (recibidos {len(key)})")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def descifrar_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """Descifra y autentica datos cifrados con AES-256-GCM."""
    if len(key) != 32:
        raise ValueError(f"AES-256 requiere una clave de 32 bytes (recibidos {len(key)})")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def cifrar_chacha20_poly1305(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Cifra datos con ChaCha20-Poly1305.
    Retorna (nonce, ciphertext_con_tag).
    """
    if len(key) != 32:
        raise ValueError(f"ChaCha20-Poly1305 requiere una clave de 32 bytes (recibidos {len(key)})")
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def descifrar_chacha20_poly1305(ciphertext: bytes, key: bytes, nonce: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """Descifra y autentica datos cifrados con ChaCha20-Poly1305."""
    if len(key) != 32:
        raise ValueError(f"ChaCha20-Poly1305 requiere una clave de 32 bytes (recibidos {len(key)})")
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, associated_data)


def generar_par_claves_ed25519() -> Tuple[bytes, bytes]:
    """
    Genera un par de claves Ed25519 para firma digital de cátedra.
    Retorna (private_key_pem, public_key_pem).
    """
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    priv_pem = priv_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pub_pem = pub_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def firmar_mensaje_ed25519(mensaje: bytes, private_key_pem: bytes) -> bytes:
    """Firma un mensaje usando una clave privada Ed25519."""
    priv_key = load_pem_private_key(private_key_pem, password=None)
    if not isinstance(priv_key, ed25519.Ed25519PrivateKey):
        raise TypeError("La clave privada provista no es de tipo Ed25519")
    return priv_key.sign(mensaje)


def verificar_firma_ed25519(mensaje: bytes, firma: bytes, public_key_pem: bytes) -> bool:
    """Verifica la firma Ed25519 de un mensaje. Retorna True si es válida, False si fue alterada."""
    pub_key = load_pem_public_key(public_key_pem)
    if not isinstance(pub_key, ed25519.Ed25519PublicKey):
        raise TypeError("La clave pública provista no es de tipo Ed25519")
    try:
        pub_key.verify(firma, mensaje)
        return True
    except InvalidSignature:
        return False
