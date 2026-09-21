"""Regresión de KEYMAKER-D0701: pytest en el grupo de desarrollo que `uv sync` instala."""

import tomllib
from pathlib import Path


def test_pytest_esta_en_dependency_groups_dev():
    datos = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert any(d.startswith("pytest") for d in datos["dependency-groups"]["dev"])
