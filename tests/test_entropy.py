"""Tests del auditor de entropía de contraseñas de Keymaker."""

from keymaker.core.entropy import auditar_frase_paso, calcular_entropia_shannon


def test_entropy_debil():
    reporte = auditar_frase_paso("123456")
    assert reporte["clasificacion"] == "DÉBIL"
    assert reporte["valida_para_examen"] is False


def test_entropy_fuerte():
    reporte = auditar_frase_paso("C@tedra_P1_Segura_2026!#$")
    assert reporte["clasificacion"] in ("FUERTE", "EXTREMA")
    assert reporte["valida_para_examen"] is True
    assert reporte["bits_entropia"] >= 80
