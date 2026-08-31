"""Tests de empaquetado y desempaquetado de bundles cifrados en Keymaker."""

from pathlib import Path
import pytest

from keymaker.core.bundle import (
    crear_bundle_cifrado,
    desempaquetar_bundle_cifrado,
    extraer_payload_a_directorio,
)
from keymaker.core.crypto import generar_par_claves_ed25519


def test_bundle_pack_unpack_roundtrip(tmp_path):
    archivo_origen = tmp_path / "enunciado.yaml"
    archivo_origen.write_text("id: tp1_lista\ntitulo: TDA Lista\n", encoding="utf-8")
    
    priv_pem, pub_pem = generar_par_claves_ed25519()
    bundle_out = tmp_path / "examen.ripkg.enc"

    meta = crear_bundle_cifrado(
        contenido_bytes=archivo_origen.read_bytes(),
        passphrase="FraseSeguraParaExamen2026!",
        output_path=bundle_out,
        private_key_pem=priv_pem,
    )
    assert bundle_out.exists()
    assert meta["checksum_sha256"] is not None

    # Desempaquetar y verificar firma
    plaintext, meta_dec = desempaquetar_bundle_cifrado(
        bundle_path=bundle_out,
        passphrase="FraseSeguraParaExamen2026!",
        public_key_pem=pub_pem,
    )
    assert plaintext == archivo_origen.read_bytes()
    assert meta_dec["checksum_sha256"] == meta["checksum_sha256"]


def test_bundle_hkdf_legajo(tmp_path):
    contenido = b"Solucion oficial para padron 12345"
    bundle_out = tmp_path / "alumno.ripkg.enc"

    crear_bundle_cifrado(
        contenido_bytes=contenido,
        passphrase="MasterPasswordCatedra2026",
        output_path=bundle_out,
        legajo="12345",
    )

    # Con el legajo correcto descifra
    plaintext, _ = desempaquetar_bundle_cifrado(
        bundle_path=bundle_out,
        passphrase="MasterPasswordCatedra2026",
        legajo="12345",
    )
    assert plaintext == contenido

    # Con legajo erróneo falla la autenticación AES-GCM
    with pytest.raises(Exception):
        desempaquetar_bundle_cifrado(
            bundle_path=bundle_out,
            passphrase="MasterPasswordCatedra2026",
            legajo="99999",
        )
