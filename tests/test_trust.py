"""Tests del repositorio público de confianza (Trust Store) y CRL en Keymaker."""

from pathlib import Path
import pytest
from typer.testing import CliRunner

from keymaker.cli import app
from keymaker.core.crypto import generar_par_claves_ed25519
from keymaker.core.trust import (
    TrustStore,
    agregar_revocacion_a_crl,
    inicializar_repo_confianza,
)

runner = CliRunner()


def test_trust_store_lifecycle(tmp_path):
    repo_dir = tmp_path / "github_trust_repo"
    priv_root, pub_root = inicializar_repo_confianza(repo_dir, issuer="catedra-test")

    store = TrustStore(repo_dir)
    assert store.crl_file.exists()
    assert store.verificar_integridad_crl() is True

    # Generar una clave de docente y comprobar que no esté revocada
    priv_doc, pub_doc = generar_par_claves_ed25519()
    revocada, _ = store.esta_revocada("docente_1", pub_doc)
    assert revocada is False

    # Revocar la clave de docente
    crl_act = agregar_revocacion_a_crl(
        trust_dir=repo_dir,
        key_id="docente_1",
        fingerprint="fp12345",
        motivo="KEY_COMPROMISE",
        root_priv_pem=priv_root,
    )
    assert len(crl_act.revoked_keys) == 1
    assert store.verificar_integridad_crl() is True

    # Ahora debe figurar como revocada
    revocada, rec = store.esta_revocada("docente_1")
    assert revocada is True
    assert rec.reason == "KEY_COMPROMISE"


def test_cli_trust_commands(tmp_path):
    repo_dir = tmp_path / "trust_repo"
    root_key = tmp_path / "root.key"

    # 1. Init repo
    res_init = runner.invoke(app, ["trust", "init-repo", str(repo_dir), "--root-key-out", str(root_key)])
    assert res_init.exit_code == 0
    assert (repo_dir / "trust_root.pub").exists()
    assert (repo_dir / "revocations/crl.json").exists()

    # 2. Generar clave para revocar
    key_doc = tmp_path / "docente.pub"
    _, pub_doc = generar_par_claves_ed25519()
    key_doc.write_bytes(pub_doc)

    # 3. Revocar
    res_rev = runner.invoke(app, [
        "trust", "revoke",
        "--key-id", "docente_perez",
        "--key-file", str(key_doc),
        "--root-key", str(root_key),
        "--trust-dir", str(repo_dir),
        "--reason", "TEACHER_DEPARTURE",
    ])
    assert res_rev.exit_code == 0
    assert "Clave revocada exitosamente" in res_rev.stdout

    # 4. Check revocation (debe fallar con exit code 1)
    res_check = runner.invoke(app, [
        "trust", "check-revocation",
        "--key-id", "docente_perez",
        "--trust-dir", str(repo_dir),
    ])
    assert res_check.exit_code == 1
    assert "CLAVE REVOCADA" in res_check.stdout
