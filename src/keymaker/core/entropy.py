"""Auditor de entropía y robustez de contraseñas y frases de paso."""

from __future__ import annotations

import math
from typing import Dict, Any, List


def calcular_entropia_shannon(texto: str) -> float:
    """Calcula la entropía de Shannon en bits por caracter."""
    if not texto:
        return 0.0
    frecuencias: Dict[str, int] = {}
    for c in texto:
        frecuencias[c] = frecuencias.get(c, 0) + 1
    longitud = len(texto)
    entropia = 0.0
    for conteo in frecuencias.values():
        p = conteo / longitud
        entropia -= p * math.log2(p)
    return entropia


def auditar_frase_paso(frase: str) -> Dict[str, Any]:
    """
    Audita la fortaleza de una frase de paso para el cifrado de exámenes docentes.
    Calcula espacio de búsqueda, bits de entropía teórica y emite recomendaciones.
    """
    if not frase:
        return {
            "longitud": 0,
            "bits_entropia": 0.0,
            "shannon_entropia": 0.0,
            "clasificacion": "NULA",
            "valida_para_examen": False,
            "recomendaciones": ["La frase de paso no puede estar vacía."],
        }

    longitud = len(frase)
    pool_size = 0
    tiene_minusculas = any(c.islower() for c in frase)
    tiene_mayusculas = any(c.isupper() for c in frase)
    tiene_digitos = any(c.isdigit() for c in frase)
    tiene_simbolos = any(not c.isalnum() for c in frase)

    if tiene_minusculas:
        pool_size += 26
    if tiene_mayusculas:
        pool_size += 26
    if tiene_digitos:
        pool_size += 10
    if tiene_simbolos:
        pool_size += 32

    # Entropía combinatoria = longitud * log2(pool_size)
    bits_entropia = longitud * math.log2(pool_size) if pool_size > 0 else 0.0
    shannon = calcular_entropia_shannon(frase)

    recomendaciones: List[str] = []
    if longitud < 12:
        recomendaciones.append("Utilizá al menos 12 caracteres (recomendado: 16+ para exámenes).")
    if not (tiene_minusculas and tiene_mayusculas and tiene_digitos and tiene_simbolos):
        recomendaciones.append("Combiná mayúsculas, minúsculas, números y símbolos especiales.")
    if "123" in frase or "password" in frase.lower() or "admin" in frase.lower():
        recomendaciones.append("Evitá patrones predecibles o secuencias numéricas simples.")

    if bits_entropia >= 80 and longitud >= 16:
        clasificacion = "EXTREMA"
        valida = True
    elif bits_entropia >= 60 and longitud >= 12:
        clasificacion = "FUERTE"
        valida = True
    elif bits_entropia >= 40:
        clasificacion = "MODERADA"
        valida = False
    else:
        clasificacion = "DÉBIL"
        valida = False

    return {
        "longitud": longitud,
        "pool_size": pool_size,
        "bits_entropia": round(bits_entropia, 2),
        "shannon_entropia": round(shannon, 2),
        "clasificacion": clasificacion,
        "valida_para_examen": valida,
        "recomendaciones": recomendaciones,
    }
