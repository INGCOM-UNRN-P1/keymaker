"""Tests de primitivas criptográficas de Keymaker."""

import os
import pytest
from keymaker.core.crypto import (
    calcular_sha256,
    cifrar_aes_gcm,
    descifrar_aes_gcm,
    cifrar_chacha20_poly1305,
    descifrar_chacha20_poly1305,
    derivar_clave_pbkdf2,
    derivar_clave_hkdf,
    generar_par_claves_ed25519,
    firmar_mensaje_ed25519,
    verificar_firma_ed25519,
)


def test_aes_gcm_roundtrip():
    key = os.urandom(32)
    plaintext = b"Examen de Algoritmos y Programacion 1 - Catedra 2026"
    nonce, ciphertext = cifrar_aes_gcm(plaintext, key, associated_data=b"parcial_1")
    decrypted = descifrar_aes_gcm(ciphertext, key, nonce, associated_data=b"parcial_1")
    assert decrypted == plaintext


def test_chacha20_poly1305_roundtrip():
    key = os.urandom(32)
    plaintext = b"Pauta de correccion docente confidencial"
    nonce, ciphertext = cifrar_chacha20_poly1305(plaintext, key)
    decrypted = descifrar_chacha20_poly1305(ciphertext, key, nonce)
    assert decrypted == plaintext


def test_hkdf_derivation():
    master = os.urandom(32)
    sub1 = derivar_clave_hkdf(master, context="legajo:12345")
    sub2 = derivar_clave_hkdf(master, context="legajo:67890")
    assert len(sub1) == 32
    assert len(sub2) == 32
    assert sub1 != sub2


def test_ed25519_signatures():
    priv, pub = generar_par_claves_ed25519()
    mensaje = b"Enunciado oficial del Trabajo Practico 1"
    firma = firmar_mensaje_ed25519(mensaje, priv)
    assert verificar_firma_ed25519(mensaje, firma, pub) is True

    # Mensaje alterado debe fallar
    assert verificar_firma_ed25519(mensaje + b" alterado", firma, pub) is False
