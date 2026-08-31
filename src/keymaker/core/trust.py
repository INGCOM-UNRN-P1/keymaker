"""Gestor de Transparencia de Claves Públicas y Revocación vía GitHub (Key Transparency & Trust Repository)."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import urllib.request
import urllib.error

from pydantic import BaseModel, Field

from keymaker.core.crypto import (
    calcular_sha256,
    firmar_mensaje_ed25519,
    verificar_firma_ed25519,
    generar_par_claves_ed25519,
)


class KeyRevocationRecord(BaseModel):
    """Registro individual de una clave pública revocada."""
    key_id: str
    fingerprint_sha256: str
    revoked_at_utc: str
    reason: str  # e.g., "KEY_COMPROMISE", "TEACHER_DEPARTURE", "SUPERSEDED", "LOST"
    replacement_key_id: Optional[str] = None


class CertificateRevocationList(BaseModel):
    """Lista de Revocación de Claves (CRL) firmada criptográficamente."""
    version: str = "1.0.0"
    issuer: str = "catedra-algoritmos-p1"
    updated_at_utc: str
    next_update_utc: Optional[str] = None
    revoked_keys: List[KeyRevocationRecord] = Field(default_factory=list)


def calcular_fingerprint_clave(public_key_pem: bytes) -> str:
    """Calcula el fingerprint SHA-256 de una clave pública PEM."""
    return calcular_sha256(public_key_pem)


class TrustStore:
    """Almacén local o sincronizado de claves públicas autorizadas y CRL."""

    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.keys_dir = root_dir / "keys"
        self.revocations_dir = root_dir / "revocations"
        self.crl_file = self.revocations_dir / "crl.json"
        self.crl_sig_file = self.revocations_dir / "crl.json.sig"
        self.trust_root_file = root_dir / "trust_root.pub"

    def cargar_crl(self) -> Optional[CertificateRevocationList]:
        if not self.crl_file.exists():
            return None
        data = json.loads(self.crl_file.read_text(encoding="utf-8"))
        return CertificateRevocationList(**data)

    def verificar_integridad_crl(self) -> bool:
        """Verifica que la CRL esté válidamente firmada por la clave raíz de confianza."""
        if not self.crl_file.exists() or not self.crl_sig_file.exists() or not self.trust_root_file.exists():
            return False
        crl_bytes = self.crl_file.read_bytes()
        sig_bytes = self.crl_sig_file.read_bytes()
        root_pub = self.trust_root_file.read_bytes()
        return verificar_firma_ed25519(crl_bytes, sig_bytes, root_pub)

    def esta_revocada(self, key_id: str, public_key_pem: Optional[bytes] = None) -> Tuple[bool, Optional[KeyRevocationRecord]]:
        """Comprueba si una clave pública ha sido revocada según la CRL."""
        crl = self.cargar_crl()
        if not crl:
            return False, None

        fingerprint = calcular_fingerprint_clave(public_key_pem) if public_key_pem else None

        for rev in crl.revoked_keys:
            if rev.key_id == key_id:
                return True, rev
            if fingerprint and rev.fingerprint_sha256 == fingerprint:
                return True, rev

        return False, None

    def obtener_clave_publica(self, key_id: str) -> Optional[bytes]:
        """Obtiene el contenido PEM de una clave pública autorizada por ID."""
        key_path = self.keys_dir / f"{key_id}.pub"
        if key_path.exists():
            return key_path.read_bytes()
        return None


def inicializar_repo_confianza(
    directorio_salida: Path,
    issuer: str = "catedra-algoritmos-p1",
    root_priv_out: Optional[Path] = None,
) -> Tuple[bytes, bytes]:
    """
    Inicializa la estructura canónica de un repositorio de confianza de GitHub:
    - trust_root.pub / trust_root.key
    - keys/
    - revocations/crl.json y crl.json.sig
    """
    directorio_salida.mkdir(parents=True, exist_ok=True)
    keys_dir = directorio_salida / "keys"
    rev_dir = directorio_salida / "revocations"
    keys_dir.mkdir(exist_ok=True)
    rev_dir.mkdir(exist_ok=True)

    # 1. Generar par de claves raíz de confianza
    priv_root, pub_root = generar_par_claves_ed25519()
    (directorio_salida / "trust_root.pub").write_bytes(pub_root)
    if root_priv_out:
        root_priv_out.parent.mkdir(parents=True, exist_ok=True)
        root_priv_out.write_bytes(priv_root)
        try:
            os.chmod(root_priv_out, 0o600)
        except Exception:
            pass

    # 2. Generar CRL inicial vacía
    now_utc = datetime.now(timezone.utc).isoformat()
    crl = CertificateRevocationList(
        version="1.0.0",
        issuer=issuer,
        updated_at_utc=now_utc,
        revoked_keys=[],
    )
    crl_json_str = crl.model_dump_json(indent=2)
    crl_path = rev_dir / "crl.json"
    crl_path.write_text(crl_json_str, encoding="utf-8")

    # 3. Firmar CRL con la clave privada raíz
    sig = firmar_mensaje_ed25519(crl_path.read_bytes(), priv_root)
    (rev_dir / "crl.json.sig").write_bytes(sig)

    # README del repo de transparencia
    readme_path = directorio_salida / "README.md"
    readme_path.write_text(
        f"# Repositorio Público de Claves y Revocación — {issuer} 🔐\n\n"
        "Este repositorio almacena las claves públicas autorizadas de la cátedra y la Lista de Revocación de Claves (CRL) oficial verificada con `keymaker`.\n\n"
        "## Verificación Local\n"
        "```bash\n"
        f"keymaker trust sync --repo {issuer}/keymaker-trust\n"
        "```\n",
        encoding="utf-8",
    )

    return priv_root, pub_root


def agregar_revocacion_a_crl(
    trust_dir: Path,
    key_id: str,
    fingerprint: str,
    motivo: str,
    root_priv_pem: bytes,
    replacement_key_id: Optional[str] = None,
) -> CertificateRevocationList:
    """Agrega una revocación a la CRL del repositorio y vuelve a firmarla con la clave raíz."""
    rev_dir = trust_dir / "revocations"
    crl_path = rev_dir / "crl.json"
    if not crl_path.exists():
        raise FileNotFoundError(f"No se encontró la CRL en {crl_path}")

    crl_data = json.loads(crl_path.read_text(encoding="utf-8"))
    crl = CertificateRevocationList(**crl_data)

    # Evitar duplicados
    crl.revoked_keys = [r for r in crl.revoked_keys if r.key_id != key_id]
    crl.revoked_keys.append(
        KeyRevocationRecord(
            key_id=key_id,
            fingerprint_sha256=fingerprint,
            revoked_at_utc=datetime.now(timezone.utc).isoformat(),
            reason=motivo,
            replacement_key_id=replacement_key_id,
        )
    )
    crl.updated_at_utc = datetime.now(timezone.utc).isoformat()

    crl_json_bytes = crl.model_dump_json(indent=2).encode("utf-8")
    crl_path.write_bytes(crl_json_bytes)

    # Re-firmar
    sig = firmar_mensaje_ed25519(crl_json_bytes, root_priv_pem)
    (rev_dir / "crl.json.sig").write_bytes(sig)

    return crl


def sincronizar_desde_github(
    repo_slug_o_url: str,
    destino_cache: Path,
    branch: str = "main",
) -> Dict[str, Any]:
    """
    Descarga o sincroniza las claves y CRL desde el repositorio público de GitHub.
    Soporta formato 'org/repo' o URL HTTPS completa.
    """
    slug = repo_slug_o_url.replace("https://github.com/", "").strip("/")
    base_url = f"https://raw.githubusercontent.com/{slug}/{branch}"

    destino_cache.mkdir(parents=True, exist_ok=True)
    keys_dir = destino_cache / "keys"
    rev_dir = destino_cache / "revocations"
    keys_dir.mkdir(exist_ok=True)
    rev_dir.mkdir(exist_ok=True)

    archivos_descargados: List[str] = []
    
    # Intentar descargar trust_root.pub, crl.json y crl.json.sig
    for rel_path in ["trust_root.pub", "revocations/crl.json", "revocations/crl.json.sig"]:
        url = f"{base_url}/{rel_path}"
        dest = destino_cache / rel_path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Keymaker-Trust-Sync/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                dest.write_bytes(resp.read())
                archivos_descargados.append(rel_path)
        except Exception as e:
            # Si es offline o repo mockeado en tests, no fallar fatalmente
            pass

    store = TrustStore(destino_cache)
    crl_valida = store.verificar_integridad_crl() if store.crl_file.exists() else False

    return {
        "repo": slug,
        "cache_dir": str(destino_cache),
        "archivos_sincronizados": archivos_descargados,
        "crl_verificada": crl_valida,
    }
