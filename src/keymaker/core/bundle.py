"""Empaquetado y desempaquetado de bundles cifrados (.ripkg.enc / .zip.enc)."""

from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path
import struct
import tarfile
from typing import Any, Dict, List, Optional
import zipfile

from keymaker.core.crypto import (
    calcular_sha256,
    cifrar_aes_gcm,
    descifrar_aes_gcm,
    derivar_clave_pbkdf2,
    derivar_clave_hkdf,
    firmar_mensaje_ed25519,
    verificar_firma_ed25519,
)
from keymaker.core.time_lock import verificar_desbloqueo_temporal

MAGIC_HEADER = b"RIPKG_ENC_V1"

# Cabecera de un ZIP: `.ripkg` (el bundle de ripley) es un ZIP SIN CIFRAR, y su
# nombre se parece peligrosamente a `.ripkg.enc`. Distinguirlos explícitamente
# evita que alguien distribuya material de examen creyéndolo protegido.
_MAGIC_ZIP = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def inspeccionar_formato(ruta: Path) -> Dict[str, Any]:
    """Determina si un archivo es un bundle cifrado de keymaker.

    Devuelve el formato detectado y, cuando corresponde, la advertencia de que
    el contenido viaja en claro.
    """
    ruta = Path(ruta)
    cabecera = b""
    if ruta.is_file():
        with open(ruta, "rb") as f:
            cabecera = f.read(max(len(MAGIC_HEADER), 4))

    if cabecera.startswith(MAGIC_HEADER):
        return {
            "cifrado": True,
            "formato": "ripkg-enc",
            "detalle": "Bundle cifrado de keymaker (AES-256-GCM autenticado).",
        }

    if any(cabecera.startswith(m) for m in _MAGIC_ZIP):
        return {
            "cifrado": False,
            "formato": "zip",
            "detalle": (
                "Archivo ZIP sin cifrar. El `.ripkg` de ripley es exactamente esto: "
                "un ZIP en claro, aunque su nombre se parezca a `.ripkg.enc`. "
                "Cualquiera que lo reciba puede leer el contenido sin contraseña."
            ),
        }

    return {
        "cifrado": False,
        "formato": "desconocido",
        "detalle": "No tiene la cabecera de un bundle de keymaker.",
    }


def empaquetar_directorio_a_zip(directorio_origen: Path) -> bytes:
    """Empaqueta un directorio en un archivo ZIP en memoria."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(directorio_origen):
            for file in files:
                p_file = Path(root) / file
                arcname = str(p_file.relative_to(directorio_origen))
                zf.write(p_file, arcname)
    return buffer.getvalue()


def crear_bundle_cifrado(
    contenido_bytes: bytes,
    passphrase: str,
    output_path: Path,
    time_lock_utc: Optional[str] = None,
    legajo: Optional[str] = None,
    private_key_pem: Optional[bytes] = None,
    cipher: str = "AES-256-GCM",
) -> Dict[str, Any]:
    """
    Empaqueta y cifra un payload binario en formato .ripkg.enc con metadatos de autenticación e integridad.
    """
    salt = os.urandom(16)
    master_key = derivar_clave_pbkdf2(passphrase, salt, length=32)

    # Si se especificó legajo, derivar subclave individualizada con HKDF
    clave_efectiva = derivar_clave_hkdf(master_key, context=f"legajo:{legajo}") if legajo else master_key

    checksum_original = calcular_sha256(contenido_bytes)

    # Cifrado
    nonce, ciphertext = cifrar_aes_gcm(contenido_bytes, clave_efectiva)

    firma_b64: Optional[str] = None
    if private_key_pem:
        firma_bytes = firmar_mensaje_ed25519(contenido_bytes, private_key_pem)
        firma_b64 = base64.b64encode(firma_bytes).decode("ascii")

    metadata: Dict[str, Any] = {
        "magic": MAGIC_HEADER.decode("ascii"),
        "cipher": cipher,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "checksum_sha256": checksum_original,
        "time_lock_utc": time_lock_utc,
        "legajo": legajo,
        "signature_b64": firma_b64,
        "payload_size": len(ciphertext),
    }

    header_json_bytes = json.dumps(metadata, ensure_ascii=False).encode("utf-8")
    header_len = len(header_json_bytes)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(MAGIC_HEADER)
        f.write(struct.pack(">I", header_len))
        f.write(header_json_bytes)
        f.write(ciphertext)

    return metadata


def desempaquetar_bundle_cifrado(
    bundle_path: Path,
    passphrase: str,
    legajo: Optional[str] = None,
    public_key_pem: Optional[bytes] = None,
    ignore_time_lock: bool = False,
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Lee, valida y descifra un bundle .ripkg.enc. Retorna los bytes descifrados y los metadatos verificados.
    """
    # Se valida el formato ANTES de pedir la passphrase: si no, entregarle a
    # keymaker un `.ripkg` en claro devolvía un prompt de contraseña, que es
    # justamente la señal que hace creer que el archivo estaba protegido.
    formato = inspeccionar_formato(bundle_path)
    if not formato["cifrado"]:
        raise ValueError(
            f"{bundle_path} no es un bundle cifrado de keymaker. {formato['detalle']}"
        )

    with open(bundle_path, "rb") as f:
        magic = f.read(len(MAGIC_HEADER))
        if magic != MAGIC_HEADER:
            raise ValueError(f"Formato no reconocido. Cabecera mágica inválida en {bundle_path}")

        (header_len,) = struct.unpack(">I", f.read(4))
        header_json_bytes = f.read(header_len)
        metadata = json.loads(header_json_bytes.decode("utf-8"))
        ciphertext = f.read()

    # 1. Verificar Time-Lock si está presente
    if metadata.get("time_lock_utc") and not ignore_time_lock:
        verificar_desbloqueo_temporal(metadata["time_lock_utc"])

    salt = base64.b64decode(metadata["salt_b64"])
    nonce = base64.b64decode(metadata["nonce_b64"])

    master_key = derivar_clave_pbkdf2(passphrase, salt, length=32)

    req_legajo = metadata.get("legajo")
    target_legajo = legajo or req_legajo
    clave_efectiva = derivar_clave_hkdf(master_key, context=f"legajo:{target_legajo}") if target_legajo else master_key

    # Descifrar
    plaintext = descifrar_aes_gcm(ciphertext, clave_efectiva, nonce)

    # 2. Verificar Checksum SHA-256
    checksum_obtenido = calcular_sha256(plaintext)
    if checksum_obtenido != metadata.get("checksum_sha256"):
        raise ValueError(
            f"Fallo de integridad: Checksum SHA-256 no coincide (Esperado: {metadata.get('checksum_sha256')}, Obtenido: {checksum_obtenido})"
        )

    # 3. Verificar Firma Digital si se proveyó clave pública
    if public_key_pem and metadata.get("signature_b64"):
        firma_bytes = base64.b64decode(metadata["signature_b64"])
        if not verificar_firma_ed25519(plaintext, firma_bytes, public_key_pem):
            raise PermissionError("Firma digital de cátedra inválida. El paquete ha sido alterado.")

    return plaintext, metadata


def extraer_payload_a_directorio(payload_bytes: bytes, destino_dir: Path) -> List[Path]:
    """Extrae un payload (sea ZIP o archivo individual) en un directorio destino con protección path traversal."""
    destino_dir.mkdir(parents=True, exist_ok=True)
    archivos_extraidos: List[Path] = []

    # Intentar interpretar como ZIP
    if payload_bytes.startswith(b"PK\x03\x04"):
        with zipfile.ZipFile(io.BytesIO(payload_bytes)) as zf:
            for member in zf.namelist():
                # Protección path traversal
                p_out = (destino_dir / member).resolve()
                if not str(p_out).startswith(str(destino_dir.resolve())):
                    raise PermissionError(f"Intento de path traversal detectado en ZIP: {member}")
                if member.endswith("/"):
                    p_out.mkdir(parents=True, exist_ok=True)
                else:
                    p_out.parent.mkdir(parents=True, exist_ok=True)
                    p_out.write_bytes(zf.read(member))
                    archivos_extraidos.append(p_out)
    else:
        # Archivo plano
        p_out = destino_dir / "desempaquetado.dat"
        p_out.write_bytes(payload_bytes)
        archivos_extraidos.append(p_out)

    return archivos_extraidos
