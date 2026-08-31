"""Tests de Shamir Secret Sharing (k de n) en Keymaker."""

import pytest
from keymaker.core.shamir import dividir_secreto, combinar_partes


def test_shamir_3_of_5():
    secreto = b"Clave_Maestra_Catedra_Super_Secreta_2026!"
    partes = dividir_secreto(secreto, k=3, n=5)
    assert len(partes) == 5

    # Cualquier combinación de 3 partes reconstruye el secreto
    rec_123 = combinar_partes([partes[0], partes[1], partes[2]])
    assert rec_123 == secreto

    rec_135 = combinar_partes([partes[0], partes[2], partes[4]])
    assert rec_135 == secreto

    rec_245 = combinar_partes([partes[1], partes[3], partes[4]])
    assert rec_245 == secreto


def test_shamir_insufficient_shares():
    secreto = b"Clave_2026"
    partes = dividir_secreto(secreto, k=3, n=5)
    # Solo 2 partes de un esquema k=3 NO reconstruyen el secreto original
    rec_incompleto = combinar_partes([partes[0], partes[1]])
    assert rec_incompleto != secreto
