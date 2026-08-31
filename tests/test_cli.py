"""Tests de la interfaz de línea de comandos de Keymaker."""

import json
from pathlib import Path
from typer.testing import CliRunner

from keymaker.cli import app

runner = CliRunner()


def test_cli_doctor():
    res = runner.invoke(app, ["doctor"])
    assert res.exit_code == 0
    assert "Diagnóstico del Subsistema Criptográfico" in res.stdout


def test_cli_audit_passphrase():
    res = runner.invoke(app, ["audit-passphrase", "Password123!", "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "bits_entropia" in data


def test_cli_gen_keys_and_sign_verify(tmp_path):
    # Generar claves
    res_gen = runner.invoke(app, ["gen-keys", "--output-dir", str(tmp_path)])
    assert res_gen.exit_code == 0
    priv = tmp_path / "catedra.key"
    pub = tmp_path / "catedra.pub"
    assert priv.exists()
    assert pub.exists()

    # Firmar archivo
    doc = tmp_path / "enunciado.txt"
    doc.write_text("Enunciado Parcial 1")
    sig = tmp_path / "enunciado.txt.sig"
    res_sign = runner.invoke(app, ["sign", str(doc), "--key", str(priv), "--output", str(sig)])
    assert res_sign.exit_code == 0
    assert sig.exists()

    # Verificar firma
    res_ver = runner.invoke(app, ["verify", str(doc), "--sig", str(sig), "--pub", str(pub)])
    assert res_ver.exit_code == 0
    assert "FIRMA VÁLIDA" in res_ver.stdout


def test_cli_split_and_combine_shares():
    res_split = runner.invoke(app, ["split-secret", "ClaveSecreta", "-k", "2", "-n", "3", "--json"])
    assert res_split.exit_code == 0
    data = json.loads(res_split.stdout)
    shares = data["shares"]
    assert len(shares) == 3

    # Combinar usando 2 shares
    arg1 = f"{shares[0]['indice']}:{shares[0]['share_b64']}"
    arg2 = f"{shares[1]['indice']}:{shares[1]['share_b64']}"

    res_comb = runner.invoke(app, ["combine-shares", arg1, arg2])
    assert res_comb.exit_code == 0
    assert "ClaveSecreta" in res_comb.stdout


def test_cli_pack_and_unpack(tmp_path):
    orig = tmp_path / "pauta.txt"
    orig.write_text("Solucion modelo oficial de catedra")

    bundle = tmp_path / "pauta.ripkg.enc"
    res_pack = runner.invoke(app, ["pack", str(orig), "-o", str(bundle), "-p", "Password12345!"])
    assert res_pack.exit_code == 0
    assert bundle.exists()

    out_dir = tmp_path / "dest"
    res_unpack = runner.invoke(app, ["unpack", str(bundle), "-o", str(out_dir), "-p", "Password12345!"])
    assert res_unpack.exit_code == 0
    assert (out_dir / "desempaquetado.dat").exists()
    assert (out_dir / "desempaquetado.dat").read_text() == "Solucion modelo oficial de catedra"
