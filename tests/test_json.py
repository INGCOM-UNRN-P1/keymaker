"""Regresión de KEYMAKER-D0401: todos los comandos ofrecen --json versionado."""

import base64
import json

import typer.main
from typer.testing import CliRunner

from keymaker.cli import app

runner = CliRunner()
PASS = "Password12345!"


def _json(res):
    datos = json.loads(res.output)
    assert datos["schema_version"] == "1.0.0"
    assert datos["herramienta"] == "keymaker"
    return datos


def test_cada_comando_declara_la_opcion_json():
    def hojas(grupo, prefijo=""):
        for nombre, cmd in grupo.commands.items():
            if hasattr(cmd, "commands"):
                yield from hojas(cmd, f"{prefijo}{nombre} ")
            else:
                yield f"{prefijo}{nombre}", cmd

    sin_json = [n for n, c in hojas(typer.main.get_command(app))
                if "--json" not in {o for p in c.params for o in getattr(p, "opts", [])}]
    assert not sin_json, f"comandos sin --json: {sin_json}"


def test_flujo_completo_en_json(tmp_path):
    doc = tmp_path / "doc.txt"
    doc.write_text("contenido")

    d = _json(runner.invoke(app, ["gen-keys", "-o", str(tmp_path), "-p", "k", "--json"]))
    priv, pub = d["clave_privada"], d["clave_publica"]

    sig = tmp_path / "doc.sig"
    assert _json(runner.invoke(app, ["sign", str(doc), "-k", priv, "-o", str(sig), "--json"]))["firma"] == str(sig)

    ver = _json(runner.invoke(app, ["verify", str(doc), "-s", str(sig), "-p", pub,
                                    "--trust-dir", str(tmp_path / "t"), "--json"]))
    assert ver["valida"] is True

    doc.write_text("alterado")
    res = runner.invoke(app, ["verify", str(doc), "-s", str(sig), "-p", pub,
                              "--trust-dir", str(tmp_path / "t"), "--json"])
    assert res.exit_code == 1 and _json(res)["valida"] is False

    bundle = tmp_path / "x.ripkg.enc"
    pack = _json(runner.invoke(app, ["pack", str(doc), "-o", str(bundle), "-p", PASS, "--json"]))
    assert pack["salida"] == str(bundle) and not pack["firmado"]

    out = tmp_path / "out"
    unpack = _json(runner.invoke(app, ["unpack", str(bundle), "-o", str(out), "-p", PASS, "--json"]))
    assert unpack["archivos"] == 1 and unpack["checksum_sha256"] == pack["checksum_sha256"]

    assert len(_json(runner.invoke(app, ["checksum", str(doc), "--json"]))["sha256"]) == 64


def test_secretos_doctor_y_confianza_en_json(tmp_path):
    split = _json(runner.invoke(app, ["split-secret", "Clave", "-k", "2", "-n", "3", "--json"]))
    partes = [f"{s['indice']}:{s['share_b64']}" for s in split["shares"][:2]]
    assert _json(runner.invoke(app, ["combine-shares", *partes, "--json"]))["secreto"] == "Clave"

    assert _json(runner.invoke(app, ["doctor", "--json"]))["ok"] is True

    repo = tmp_path / "trust"
    _json(runner.invoke(app, ["trust", "init-repo", str(repo), "-k", str(tmp_path / "root.key"), "--json"]))
    chk = _json(runner.invoke(app, ["trust", "check-revocation", "--key-id", "nadie",
                                    "--trust-dir", str(repo), "--json"]))
    assert chk["revocada"] is False

    pub = repo / "trust_root.pub"
    rev = _json(runner.invoke(app, ["trust", "revoke", "-i", "docente", "-f", str(pub),
                                    "-k", str(tmp_path / "root.key"), "-t", str(repo), "--json"]))
    assert rev["total_revocadas"] == 1
    res = runner.invoke(app, ["trust", "check-revocation", "--key-id", "docente",
                              "--trust-dir", str(repo), "--json"])
    assert res.exit_code == 1 and _json(res)["revocada"] is True
