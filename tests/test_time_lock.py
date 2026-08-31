"""Tests de políticas Time-Lock en Keymaker."""

from datetime import datetime, timedelta, timezone
import pytest
from keymaker.core.time_lock import verificar_desbloqueo_temporal, TimeLockError


def test_time_lock_past_allows_unlock():
    past_iso = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    res = verificar_desbloqueo_temporal(past_iso)
    assert res["desbloqueado"] is True


def test_time_lock_future_raises():
    future_iso = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    with pytest.raises(TimeLockError) as exc_info:
        verificar_desbloqueo_temporal(future_iso)
    assert "Faltan" in str(exc_info.value)


def test_time_lock_override():
    future_iso = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    res = verificar_desbloqueo_temporal(future_iso, forzar_override=True)
    assert res["desbloqueado"] is True
    assert res["motivo"] == "OVERRIDE_DOCENTE"
