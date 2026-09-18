"""Regresión de KEYMAKER-D0901: `.ripkg` (ZIP en claro) vs `.ripkg.enc` (cifrado).

El `.ripkg` de ripley es un ZIP sin cifrar y su nombre se parece a
`.ripkg.enc`. Antes, dárselo a `unpack` producía un prompt de contraseña —la
señal que hace creer que el archivo estaba protegido— y recién después fallaba.
"""

import io
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from keymaker.cli import app
from keymaker.core.bundle import crear_bundle_cifrado, inspeccionar_formato

runner = CliRunner()


@pytest.fixture
def ripkg_plano(tmp_path):
    """Un `.ripkg` tal como lo produce ripley: ZIP sin cifrar."""
    ruta = tmp_path / "practica.ripkg"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("examen.txt", "enunciado secreto")
    ruta.write_bytes(buffer.getvalue())
    return ruta


@pytest.fixture
def bundle_cifrado(tmp_path):
    ruta = tmp_path / "examen.ripkg.enc"
    crear_bundle_cifrado(b"enunciado secreto", "clave-de-prueba", ruta)
    return ruta


def test_detecta_el_zip_en_claro(ripkg_plano):
    formato = inspeccionar_formato(ripkg_plano)
    assert formato["cifrado"] is False
    assert formato["formato"] == "zip"
    assert "sin cifrar" in formato["detalle"].lower()


def test_detecta_el_bundle_cifrado(bundle_cifrado):
    formato = inspeccionar_formato(bundle_cifrado)
    assert formato["cifrado"] is True
    assert formato["formato"] == "ripkg-enc"


def test_unpack_rechaza_el_zip_sin_pedir_contrasena(ripkg_plano, tmp_path):
    """Sin passphrase en la línea de comandos: si preguntara, el test colgaría."""
    res = runner.invoke(app, ["unpack", str(ripkg_plano), "--output", str(tmp_path / "out")])
    assert res.exit_code == 2
    assert "no es un bundle cifrado" in res.output


def test_inspect_distingue_ambos(ripkg_plano, bundle_cifrado):
    plano = runner.invoke(app, ["inspect", str(ripkg_plano)])
    cifrado = runner.invoke(app, ["inspect", str(bundle_cifrado)])
    assert plano.exit_code == 1 and "SIN CIFRAR" in plano.output
    assert cifrado.exit_code == 0 and "CIFRADO" in cifrado.output


def test_inspect_json_expone_el_veredicto(bundle_cifrado):
    import json

    res = runner.invoke(app, ["inspect", str(bundle_cifrado), "--json"])
    assert json.loads(res.output)["cifrado"] is True


def test_un_archivo_cualquiera_no_se_confunde_con_un_bundle(tmp_path):
    suelto = tmp_path / "notas.txt"
    suelto.write_text("texto plano", encoding="utf-8")
    assert inspeccionar_formato(suelto)["formato"] == "desconocido"
