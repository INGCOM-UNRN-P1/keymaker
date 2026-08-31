"""Esquema de División de Secretos de Shamir (k de n) sobre el cuerpo finito GF(256)."""

from __future__ import annotations

import secrets
from typing import List, Tuple

# Tablas de exponenciación y logaritmo para aritmética en GF(256) con polinomio 0x11B y generador 0x03
_EXP = [0] * 512
_LOG = [0] * 256

def _init_gf256():
    poly = 0x11B
    x = 1
    for i in range(255):
        _EXP[i] = x
        _EXP[i + 255] = x
        _LOG[x] = i
        # Multiplicación x * 3 en GF(2^8)
        hi = x & 0x80
        x2 = ((x << 1) ^ (poly if hi else 0)) & 0xFF
        x = x2 ^ x
    _LOG[0] = 0

_init_gf256()


def _gf_add(a: int, b: int) -> int:
    return a ^ b


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[(_LOG[a] + _LOG[b]) % 255]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("División por cero en GF(256)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b] + 255) % 255]


def _eval_poly(poly: List[int], x: int) -> int:
    """Evalúa un polinomio P(x) = poly[0] + poly[1]*x + ... en GF(256) usando Horner."""
    res = 0
    for coef in reversed(poly):
        res = _gf_add(_gf_mul(res, x), coef)
    return res


def dividir_secreto(secreto: bytes, k: int, n: int) -> List[Tuple[int, bytes]]:
    """
    Divide un secreto en 'n' partes (shares), requiriendo al menos 'k' partes para reconstruirlo.
    Retorna una lista de tuplas: [(1, share1_bytes), (2, share2_bytes), ..., (n, share_n_bytes)].
    """
    if k > n:
        raise ValueError(f"El umbral k={k} no puede ser mayor que el total n={n}")
    if k < 2:
        raise ValueError(f"El umbral k debe ser al menos 2 (recibido {k})")
    if n > 254:
        raise ValueError(f"El número máximo de partes en GF(256) es 254 (recibido {n})")

    shares_data = [bytearray() for _ in range(n)]

    for byte_val in secreto:
        # Polinomio: P(x) = byte_val + c1*x + c2*x^2 + ... + c_{k-1}*x^{k-1}
        coefs = [byte_val] + [secrets.randbelow(256) for _ in range(k - 1)]
        for i in range(1, n + 1):
            val_y = _eval_poly(coefs, i)
            shares_data[i - 1].append(val_y)

    return [(i, bytes(shares_data[i - 1])) for i in range(1, n + 1)]


def combinar_partes(partes: List[Tuple[int, bytes]]) -> bytes:
    """
    Reconstruye el secreto original a partir de al menos 'k' partes mediante interpolación de Lagrange en x=0.
    Cada parte es una tupla (x_i, data_bytes).
    """
    if not partes:
        raise ValueError("No se proporcionaron partes para reconstruir el secreto")

    k = len(partes)
    longitud = len(partes[0][1])
    for x, data in partes:
        if len(data) != longitud:
            raise ValueError("Todas las partes deben tener la misma longitud de bytes")

    xs = [x for x, _ in partes]
    if len(set(xs)) != len(xs):
        raise ValueError("Existen partes duplicadas con el mismo índice x")

    secreto = bytearray(longitud)

    for byte_idx in range(longitud):
        valor_byte = 0
        for i in range(k):
            xi, data_i = partes[i]
            yi = data_i[byte_idx]

            # Calcular base de Lagrange L_i(0) = PROD_{j != i} (0 - x_j) / (x_i - x_j)
            li = 1
            for j in range(k):
                if i != j:
                    xj, _ = partes[j]
                    num = xj
                    den = _gf_add(xi, xj)
                    li = _gf_mul(li, _gf_div(num, den))

            valor_byte = _gf_add(valor_byte, _gf_mul(yi, li))

        secreto[byte_idx] = valor_byte

    return bytes(secreto)
