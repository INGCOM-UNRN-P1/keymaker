"""Gestión de políticas de desbloqueo temporal (Time-Lock) para paquetes de examen."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Any, Optional


class TimeLockError(PermissionError):
    """Excepción lanzada cuando se intenta descifrar un examen antes de su hora de inicio."""
    pass


def parsear_timestamp_utc(iso_str: str) -> datetime:
    """Parsea una cadena ISO-8601 a datetime UTC con zona horaria explícita."""
    dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def verificar_desbloqueo_temporal(
    unlock_at_iso: str,
    now: Optional[datetime] = None,
    forzar_override: bool = False,
) -> Dict[str, Any]:
    """
    Verifica si la fecha/hora actual superó la marca de tiempo de desbloqueo oficial.
    Retorna un diccionario de estado con segundos restantes.
    """
    if forzar_override:
        return {
            "desbloqueado": True,
            "motivo": "OVERRIDE_DOCENTE",
            "segundos_restantes": 0,
        }

    unlock_dt = parsear_timestamp_utc(unlock_at_iso)
    current_dt = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    segundos_restantes = (unlock_dt - current_dt).total_seconds()

    if segundos_restantes > 0:
        raise TimeLockError(
            f"El paquete de examen se encuentra bloqueado temporalmente hasta {unlock_dt.isoformat()}. "
            f"Faltan {int(segundos_restantes)} segundos para su apertura oficial."
        )

    return {
        "desbloqueado": True,
        "unlock_at": unlock_dt.isoformat(),
        "now": current_dt.isoformat(),
        "segundos_transcurridos": abs(int(segundos_restantes)),
    }
