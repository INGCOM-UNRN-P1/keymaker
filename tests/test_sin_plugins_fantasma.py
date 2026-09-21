"""Regresión de KEYMAKER-D0902: no declarar un grupo de plugins que nadie carga."""

import tomllib
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]


def test_todo_grupo_de_entry_points_declarado_tiene_al_menos_un_plugin():
    datos = tomllib.loads((RAIZ / "pyproject.toml").read_text(encoding="utf-8"))
    for grupo, plugins in datos["project"].get("entry-points", {}).items():
        assert plugins, f"grupo de entry-points vacío: {grupo}"


def test_el_grupo_keymaker_plugins_solo_existe_si_el_codigo_lo_consume():
    datos = tomllib.loads((RAIZ / "pyproject.toml").read_text(encoding="utf-8"))
    declarado = "keymaker.plugins" in datos["project"].get("entry-points", {})
    consumido = any("keymaker.plugins" in f.read_text(encoding="utf-8")
                    for f in (RAIZ / "src").rglob("*.py"))
    assert declarado == consumido
