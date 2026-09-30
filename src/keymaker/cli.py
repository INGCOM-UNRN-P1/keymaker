"""CLI principal de Keymaker — Gestor de cifrado, integridad y repositorio de confianza de exámenes."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import List, Optional
import typer
from yutani.cli import crear_app
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from keymaker import __version__
from keymaker.core.bundle import (
    inspeccionar_formato,
    crear_bundle_cifrado,
    desempaquetar_bundle_cifrado,
    empaquetar_directorio_a_zip,
    extraer_payload_a_directorio,
)
from keymaker.core.crypto import (
    calcular_sha256_archivo,
    firmar_mensaje_ed25519,
    generar_par_claves_ed25519,
    verificar_firma_ed25519,
)
from keymaker.core.doctor import ejecutar_diagnostico_doctor
from keymaker.core.entropy import auditar_frase_paso
from keymaker.core.shamir import combinar_partes, dividir_secreto
from keymaker.core.time_lock import ADVERTENCIA_TIME_LOCK
from keymaker.core.trust import (
    TrustStore,
    agregar_revocacion_a_crl,
    calcular_fingerprint_clave,
    inicializar_repo_confianza,
    sincronizar_desde_github,
)

# Contrato de línea de comandos del ecosistema (-h/--help, --version/-v, errores de datos como
# mensajes) y textos de Typer en español, desde yutani (N-ECO-14).
app = crear_app(
    "keymaker",
    __version__,
    "🔐 Keymaker — Gestor de cifrado simétrico autenticado (AES-GCM), firmas Ed25519, Time-Lock y Trust Store.",
)
trust_app = typer.Typer(
    name="trust",
    help="🛡️ Gestión de claves públicas autorizadas y Lista de Revocación (CRL) en GitHub.",
    no_args_is_help=True,
)
app.add_typer(trust_app, name="trust")

console = Console()
err_console = Console(stderr=True)

DEFAULT_TRUST_DIR = Path.home() / ".keymaker" / "trust"

SCHEMA_VERSION = "1.0.0"
JSON_OPT = "Emitir el resultado en JSON versionado (schema_version)."


def _emitir_json(comando: str, datos: dict) -> None:
    """Imprime `datos` como JSON con el envoltorio común de todos los comandos."""
    payload = {"schema_version": SCHEMA_VERSION, "herramienta": "keymaker", "comando": comando}
    payload.update(datos)
    print(json.dumps(payload, indent=2, ensure_ascii=False))


@app.command("pack")
@app.command("encrypt")
def cmd_pack(
    origen: Path = typer.Argument(..., help="Archivo o directorio a empaquetar y cifrar.", exists=True),
    output: Path = typer.Option(..., "--output", "-o", help="Ruta del archivo de salida (.ripkg.enc)."),
    passphrase: str = typer.Option(..., "--passphrase", "-p", prompt=True, hide_input=True, help="Frase de paso para cifrado."),
    time_lock: Optional[str] = typer.Option(
        None, "--time-lock", "-t",
        help="Fecha/hora UTC de desbloqueo (ej: 2026-09-15T09:00:00Z). Disuasivo: se verifica con el reloj local.",
    ),
    legajo: Optional[str] = typer.Option(None, "--legajo", "-l", help="Legajo de estudiante para derivación HKDF."),
    signing_key: Optional[Path] = typer.Option(None, "--sign-key", "-s", help="Clave privada Ed25519 (.key) para firmar digitalmente."),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Empaqueta y cifra un examen o pauta en un bundle autenticado (.ripkg.enc)."""
    if origen.is_dir():
        payload_bytes = empaquetar_directorio_a_zip(origen)
    else:
        payload_bytes = origen.read_bytes()

    priv_pem: Optional[bytes] = None
    if signing_key:
        if not signing_key.exists():
            err_console.print(f"[bold red]No existe la clave privada: {signing_key}[/bold red]")
            raise typer.Exit(code=1)
        priv_pem = signing_key.read_bytes()

    meta = crear_bundle_cifrado(
        contenido_bytes=payload_bytes,
        passphrase=passphrase,
        output_path=output,
        time_lock_utc=time_lock,
        legajo=legajo,
        private_key_pem=priv_pem,
    )

    if json_output:
        datos = {"salida": str(output), "algoritmo": meta["cipher"],
                 "checksum_sha256": meta["checksum_sha256"],
                 "time_lock_utc": meta["time_lock_utc"], "legajo": meta["legajo"],
                 "firmado": bool(meta["signature_b64"])}
        if meta["time_lock_utc"]:
            datos["advertencia_time_lock"] = ADVERTENCIA_TIME_LOCK
        _emitir_json("pack", datos)
        return

    console.print(Panel(
        f"[bold green]✓ Paquete cifrado exitosamente en:[/bold green] [cyan]{output}[/cyan]\n\n"
        f"• **Algoritmo:** `{meta['cipher']}`\n"
        f"• **Checksum SHA-256:** `{meta['checksum_sha256']}`\n"
        f"• **Bloqueo Temporal (Time-Lock):** `{meta['time_lock_utc'] or 'Inmediato (Sin restricción)'}`\n"
        f"• **Derivación por Legajo:** `{meta['legajo'] or 'Global'}`\n"
        f"• **Firma Digital Ed25519:** `{'✓ FIRMADO' if meta['signature_b64'] else 'No firmada'}`",
        title="[bold cyan]Keymaker Pack[/bold cyan]",
        border_style="green",
    ))
    if meta["time_lock_utc"]:
        console.print(f"[yellow]⚠ {ADVERTENCIA_TIME_LOCK}[/yellow]")


def _validar_bundle_cifrado(valor: Path) -> Path:
    """Rechaza archivos que no son bundles cifrados antes de pedir la passphrase.

    Pedir la contraseña sobre un `.ripkg` en claro es la señal que hace creer
    que el archivo estaba protegido; el `.ripkg` de ripley es un ZIP sin
    cifrar pese al parecido de nombres con `.ripkg.enc`.
    """
    if valor is None:
        return valor
    formato = inspeccionar_formato(valor)
    if not formato["cifrado"]:
        err_console.print(
            f"[bold red]❌ {valor} no es un bundle cifrado de keymaker.[/bold red]\n"
            f"{formato['detalle']}"
        )
        raise typer.Exit(code=2)
    return valor


@app.command("inspect")
def cmd_inspect(
    archivo: Path = typer.Argument(..., help="Archivo a inspeccionar.", exists=True),
    json_output: bool = typer.Option(False, "--json", help="Emitir el resultado en JSON."),
) -> None:
    """Informa si un archivo está realmente cifrado por keymaker o viaja en claro."""
    formato = inspeccionar_formato(archivo)

    if json_output:
        _emitir_json("inspect", {"archivo": str(archivo), **formato})
        raise typer.Exit(code=0 if formato["cifrado"] else 1)

    if formato["cifrado"]:
        console.print(f"[bold green]🔒 CIFRADO[/bold green] — {archivo}")
        console.print(formato["detalle"])
        raise typer.Exit(code=0)

    console.print(f"[bold red]🔓 SIN CIFRAR[/bold red] — {archivo}")
    console.print(formato["detalle"])
    raise typer.Exit(code=1)


@app.command("unpack")
@app.command("decrypt")
def cmd_unpack(
    bundle: Path = typer.Argument(
        ...,
        help="Ruta al archivo cifrado (.ripkg.enc).",
        exists=True,
        callback=_validar_bundle_cifrado,
    ),
    output_dir: Path = typer.Option(Path("./desempaquetado"), "--output", "-o", help="Directorio destino para extraer el contenido."),
    passphrase: str = typer.Option(..., "--passphrase", "-p", prompt=True, hide_input=True, help="Frase de paso para descifrado."),
    legajo: Optional[str] = typer.Option(None, "--legajo", "-l", help="Legajo de estudiante para derivación HKDF."),
    verify_key: Optional[Path] = typer.Option(None, "--verify-key", "-v", help="Clave pública Ed25519 (.pub) para verificar la firma."),
    force_unlock: bool = typer.Option(False, "--force", "-f", help="Forzar desbloqueo docente omitiendo el Time-Lock."),
    trust_dir: Path = typer.Option(DEFAULT_TRUST_DIR, "--trust-dir", help="Directorio del Trust Store para verificar revocaciones."),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Descifra, verifica la integridad y extrae el contenido de un bundle (.ripkg.enc)."""
    if force_unlock and not verify_key:
        err_console.print("[bold red]❌ Error de autenticación:[/bold red] El forzado de Time-Lock (--force) requiere autenticación docente mediante clave pública autorizada (--verify-key).")
        raise typer.Exit(code=1)

    pub_pem: Optional[bytes] = None
    if verify_key:
        if not verify_key.exists():
            err_console.print(f"[bold red]No existe la clave pública: {verify_key}[/bold red]")
            raise typer.Exit(code=1)
        pub_pem = verify_key.read_bytes()

        # Comprobar si la clave está revocada
        store = TrustStore(trust_dir)
        revocada, rec = store.esta_revocada(key_id=verify_key.stem, public_key_pem=pub_pem)
        if revocada and rec:
            err_console.print(f"[bold red]❌ CLAVE REVOCADA:[/bold red] La clave {rec.key_id} fue revocada el {rec.revoked_at_utc}. Motivo: {rec.reason}")
            raise typer.Exit(code=1)

    try:
        plaintext, meta = desempaquetar_bundle_cifrado(
            bundle_path=bundle,
            passphrase=passphrase,
            legajo=legajo,
            public_key_pem=pub_pem,
            ignore_time_lock=force_unlock,
        )
    except Exception as e:
        err_console.print(f"[bold red]❌ Error de apertura:[/bold red] {e}")
        raise typer.Exit(code=1)

    archivos = extraer_payload_a_directorio(plaintext, output_dir)

    if json_output:
        _emitir_json("unpack", {"directorio": str(output_dir), "archivos": len(archivos),
                                "checksum_sha256": meta["checksum_sha256"],
                                "firma_verificada": pub_pem is not None})
        return

    console.print(Panel(
        f"[bold green]✓ Paquete descifrado y verificado exitosamente en:[/bold green] [cyan]{output_dir}[/cyan]\n\n"
        f"• **Archivos extraídos:** {len(archivos)}\n"
        f"• **Integridad SHA-256:** `[green]VERIFICADA[/green]` (`{meta['checksum_sha256'][:16]}...`)\n"
        f"• **Autenticación Ed25519:** `{'[green]VÁLIDA[/green]' if pub_pem else '[dim]No requerida[/dim]'}`",
        title="[bold cyan]Keymaker Unpack[/bold cyan]",
        border_style="green",
    ))


@app.command("gen-keys")
def cmd_gen_keys(
    prefix: str = typer.Option("catedra", "--prefix", "-p", help="Prefijo de los archivos de clave generados."),
    out_dir: Path = typer.Option(Path("."), "--output-dir", "-o", help="Directorio donde guardar las claves."),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Genera un nuevo par de claves asimétricas Ed25519 para firma digital de exámenes."""
    priv_pem, pub_pem = generar_par_claves_ed25519()

    out_dir.mkdir(parents=True, exist_ok=True)
    priv_file = out_dir / f"{prefix}.key"
    pub_file = out_dir / f"{prefix}.pub"

    priv_file.write_bytes(priv_pem)
    pub_file.write_bytes(pub_pem)
    try:
        os.chmod(priv_file, 0o600)
    except Exception:
        pass

    if json_output:
        _emitir_json("gen-keys", {"clave_privada": str(priv_file), "clave_publica": str(pub_file)})
        return

    console.print(f"[bold green]✓ Par de claves Ed25519 generado exitosamente:[/bold green]")
    console.print(f"  • [bold]Clave Privada (Firma):[/bold] [cyan]{priv_file}[/cyan] (chmod 600)")
    console.print(f"  • [bold]Clave Pública (Verificación):[/bold] [cyan]{pub_file}[/cyan]")


@app.command("sign")
def cmd_sign(
    archivo: Path = typer.Argument(..., help="Archivo a firmar.", exists=True),
    key_file: Path = typer.Option(..., "--key", "-k", help="Ruta a la clave privada Ed25519 (.key).", exists=True),
    sig_output: Optional[Path] = typer.Option(None, "--output", "-o", help="Archivo de firma de salida (.sig)."),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Firma un archivo con una clave privada Ed25519."""
    data = archivo.read_bytes()
    priv_pem = key_file.read_bytes()
    sig = firmar_mensaje_ed25519(data, priv_pem)

    out_path = sig_output or archivo.with_suffix(archivo.suffix + ".sig")
    out_path.write_bytes(sig)
    if json_output:
        _emitir_json("sign", {"archivo": str(archivo), "firma": str(out_path)})
        return
    console.print(f"[bold green]✓ Firma digital generada en:[/bold green] [cyan]{out_path}[/cyan]")


@app.command("verify")
def cmd_verify(
    archivo: Path = typer.Argument(..., help="Archivo a verificar.", exists=True),
    sig_file: Path = typer.Option(..., "--sig", "-s", help="Archivo de firma (.sig).", exists=True),
    pub_file: Path = typer.Option(..., "--pub", "-p", help="Clave pública Ed25519 (.pub).", exists=True),
    trust_dir: Path = typer.Option(DEFAULT_TRUST_DIR, "--trust-dir", help="Directorio del Trust Store para verificar revocaciones."),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Verifica la firma digital Ed25519 de un archivo consultando el Trust Store."""
    data = archivo.read_bytes()
    sig = sig_file.read_bytes()
    pub_pem = pub_file.read_bytes()

    # Comprobar revocación
    store = TrustStore(trust_dir)
    revocada, rec = store.esta_revocada(key_id=pub_file.stem, public_key_pem=pub_pem)
    if revocada and rec:
        if json_output:
            _emitir_json("verify", {"archivo": str(archivo), "valida": False, "revocada": True,
                                    "key_id": rec.key_id, "motivo": rec.reason})
            raise typer.Exit(code=1)
        err_console.print(f"[bold red]❌ CLAVE REVOCADA:[/bold red] La clave {rec.key_id} está revocada desde {rec.revoked_at_utc} (Motivo: {rec.reason}).")
        raise typer.Exit(code=1)

    valida = verificar_firma_ed25519(data, sig, pub_pem)
    if json_output:
        _emitir_json("verify", {"archivo": str(archivo), "valida": valida, "revocada": False})
        raise typer.Exit(code=0 if valida else 1)

    if valida:
        console.print(f"[bold green]✓ FIRMA VÁLIDA:[/bold green] El archivo [cyan]{archivo}[/cyan] es auténtico y no fue modificado.")
    else:
        err_console.print(f"[bold red]❌ FIRMA INVÁLIDA:[/bold red] El archivo [cyan]{archivo}[/cyan] ha sido alterado o la clave pública es incorrecta.")
        raise typer.Exit(code=1)


@app.command("split-secret")
def cmd_split_secret(
    secreto: str = typer.Argument(..., help="Texto o frase de paso a dividir."),
    k: int = typer.Option(..., "-k", help="Umbral mínimo de partes requeridas para descifrar."),
    n: int = typer.Option(..., "-n", help="Cantidad total de partes a generar."),
    json_output: bool = typer.Option(False, "--json", help="Emitir salida en formato JSON."),
) -> None:
    """Divide un secreto docente en N partes usando el esquema de Shamir (k de n)."""
    partes = dividir_secreto(secreto.encode("utf-8"), k=k, n=n)

    shares_formatted = [
        {"indice": idx, "share_b64": base64.b64encode(data).decode("ascii")}
        for idx, data in partes
    ]

    if json_output:
        _emitir_json("split-secret", {"k": k, "n": n, "shares": shares_formatted})
        return

    console.print(Panel(
        f"[bold cyan]División de Secreto de Shamir[/bold cyan] (Esquema {k} de {n})\n\n"
        f"Se generaron [green]{n}[/green] partes. Se requiere reunir al menos [yellow]{k}[/yellow] partes cualesquiera para reconstruir el secreto original.",
        title="[bold green]✓ Secreto Dividido[/bold green]",
        border_style="cyan",
    ))

    tabla = Table(title="Partes Generadas (Distribución Docente)", border_style="cyan")
    tabla.add_column("Parte #", justify="center", style="bold white")
    tabla.add_column("Share (Base64)", style="green")

    for s in shares_formatted:
        tabla.add_row(str(s["indice"]), s["share_b64"])

    console.print(tabla)


@app.command("combine-shares")
def cmd_combine_shares(
    shares: List[str] = typer.Argument(..., help="Partes en formato 'indice:share_b64' (ej: '1:Ag4F...' '3:Bw8Z...')."),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Reconstruye un secreto a partir de K partes de Shamir."""
    partes_tuplas = []
    for s in shares:
        if ":" not in s:
            err_console.print(f"[bold red]Formato inválido en parte '{s}'. Debe ser 'indice:share_base64'.[/bold red]")
            raise typer.Exit(code=1)
        idx_s, b64_s = s.split(":", 1)
        partes_tuplas.append((int(idx_s), base64.b64decode(b64_s)))

    try:
        secreto_bytes = combinar_partes(partes_tuplas)
        secreto_str = secreto_bytes.decode("utf-8")
    except Exception as e:
        err_console.print(f"[bold red]❌ Error al reconstruir el secreto:[/bold red] {e}")
        raise typer.Exit(code=1)

    if json_output:
        _emitir_json("combine-shares", {"partes": len(partes_tuplas), "secreto": secreto_str})
        return

    console.print(f"\n[bold green]✓ Secreto reconstruido con éxito:[/bold green] [bold cyan]{secreto_str}[/bold cyan]\n")


@app.command("audit-passphrase")
def cmd_audit_passphrase(
    frase: str = typer.Argument(..., help="Frase de paso a auditar."),
    json_output: bool = typer.Option(False, "--json", help="Emitir reporte en JSON."),
) -> None:
    """Audita la entropía y robustez criptográfica de una frase de paso para exámenes."""
    reporte = auditar_frase_paso(frase)

    if json_output:
        _emitir_json("audit-passphrase", reporte)
        return

    color = "green" if reporte["valida_para_examen"] else "red"
    console.print(Panel(
        f"• **Longitud:** {reporte['longitud']} caracteres\n"
        f"• **Entropía Combinatoria:** [bold]{reporte['bits_entropia']} bits[/bold]\n"
        f"• **Entropía de Shannon:** {reporte['shannon_entropia']} bits/char\n"
        f"• **Calificación:** [{color}]{reporte['clasificacion']}[/{color}]\n"
        f"• **Apta para Examen:** {'[green]✓ SÍ[/green]' if reporte['valida_para_examen'] else '[red]❌ INSUFICIENTE[/red]'}",
        title="[bold cyan]Auditoría de Frase de Paso[/bold cyan]",
        border_style=color,
    ))

    if reporte["recomendaciones"]:
        console.print("\n[bold yellow]Sugerencias de mejora:[/bold yellow]")
        for rec in reporte["recomendaciones"]:
            console.print(f"  • {rec}")


@app.command("checksum")
def cmd_checksum(
    archivo: Path = typer.Argument(..., help="Archivo a calcular hash SHA-256.", exists=True),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Calcula el checksum SHA-256 de un archivo para control de integridad."""
    h = calcular_sha256_archivo(str(archivo))
    if json_output:
        _emitir_json("checksum", {"archivo": str(archivo), "sha256": h})
        return
    console.print(f"[bold white]{h}[/bold white]  [cyan]{archivo}[/cyan]")


@app.command("doctor")
def cmd_doctor(
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Ejecuta el diagnóstico integral del subsistema criptográfico."""
    diag = ejecutar_diagnostico_doctor(console=Console(quiet=True) if json_output else console)
    if json_output:
        _emitir_json("doctor", {"ok": diag["todo_ok"], **{k: v for k, v in diag.items() if k != "todo_ok"}})
        raise typer.Exit(code=0 if diag["todo_ok"] else 1)
    if not diag["todo_ok"]:
        raise typer.Exit(code=1)


# ==============================================================================
# SUBCOMANDOS DE GESTIÓN DE TRANSPARENCIA Y REVOCACIÓN EN GITHUB (keymaker trust)
# ==============================================================================

@trust_app.command("init-repo")
def cmd_trust_init_repo(
    directorio: Path = typer.Argument(..., help="Directorio local para inicializar el repositorio de confianza de GitHub."),
    issuer: str = typer.Option("catedra-algoritmos-p1", "--issuer", "-i", help="Identificador institucional de la cátedra emisora."),
    root_key_out: Optional[Path] = typer.Option(None, "--root-key-out", "-k", help="Ruta donde guardar la clave privada raíz (trust_root.key)."),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Inicializa la estructura canónica de un repositorio público de GitHub para claves y CRL."""
    priv, pub = inicializar_repo_confianza(
        directorio_salida=directorio,
        issuer=issuer,
        root_priv_out=root_key_out,
    )
    if json_output:
        _emitir_json("trust init-repo", {"directorio": str(directorio), "emisor": issuer,
                                         "clave_raiz_publica": str(directorio / "trust_root.pub"),
                                         "crl": str(directorio / "revocations/crl.json")})
        return
    console.print(Panel(
        f"[bold green]✓ Repositorio de Confianza de GitHub inicializado en:[/bold green] [cyan]{directorio}[/cyan]\n\n"
        f"• **Emisor Raíz:** `{issuer}`\n"
        f"• **Clave Raíz Pública:** `{directorio / 'trust_root.pub'}`\n"
        f"• **Directorio de Claves Autorizadas:** `{directorio / 'keys'}`\n"
        f"• **Lista de Revocación:** `{directorio / 'revocations/crl.json'}` (firmada)\n\n"
        "[yellow]Siguiente paso:[/yellow] Creá el repo público en GitHub y hacé `git push origin main`.",
        title="[bold cyan]Keymaker Trust Init[/bold cyan]",
        border_style="green",
    ))


@trust_app.command("sync")
def cmd_trust_sync(
    repo: str = typer.Option("catedra-p1/keymaker-trust", "--repo", "-r", help="Slug del repositorio público en GitHub (org/repo) o URL HTTPS."),
    cache_dir: Path = typer.Option(DEFAULT_TRUST_DIR, "--cache-dir", "-c", help="Directorio local para cachear las claves y la CRL."),
    branch: str = typer.Option("main", "--branch", "-b", help="Rama del repositorio de GitHub."),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Descarga y sincroniza las claves públicas autorizadas y la CRL desde un repo público de GitHub."""
    res = sincronizar_desde_github(repo_slug_o_url=repo, destino_cache=cache_dir, branch=branch)
    if json_output:
        _emitir_json("trust sync", {"repo": res["repo"], "cache_dir": str(res["cache_dir"]),
                                    "archivos_sincronizados": len(res["archivos_sincronizados"]),
                                    "crl_verificada": bool(res["crl_verificada"])})
        return
    console.print(Panel(
        f"[bold green]✓ Sincronización de confianza completada desde:[/bold green] [cyan]{res['repo']}[/cyan]\n\n"
        f"• **Caché local:** `{res['cache_dir']}`\n"
        f"• **Archivos sincronizados:** {len(res['archivos_sincronizados'])}\n"
        f"• **Integridad de CRL:** `{'[green]✓ FIRMA VÁLIDA[/green]' if res['crl_verificada'] else '[dim]Pendiente o sin raíz[/dim]'}`",
        title="[bold cyan]Keymaker Trust Sync[/bold cyan]",
        border_style="green",
    ))


@trust_app.command("revoke")
def cmd_trust_revoke(
    key_id: str = typer.Option(..., "--key-id", "-i", help="Identificador de la clave pública a revocar (ej: 'docente-garcia-2025')."),
    key_file: Path = typer.Option(..., "--key-file", "-f", help="Archivo de clave pública (.pub) para extraer el fingerprint.", exists=True),
    reason: str = typer.Option("KEY_COMPROMISE", "--reason", "-r", help="Motivo: 'KEY_COMPROMISE', 'SUPERSEDED', 'TEACHER_DEPARTURE', 'LOST'."),
    root_key: Path = typer.Option(..., "--root-key", "-k", help="Clave privada raíz Ed25519 (trust_root.key) para firmar la revocación.", exists=True),
    trust_dir: Path = typer.Option(DEFAULT_TRUST_DIR, "--trust-dir", "-t", help="Directorio raíz del repositorio de confianza local.", exists=True),
    replacement_id: Optional[str] = typer.Option(None, "--replacement", help="ID de la clave de reemplazo si aplica."),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Revoca una clave pública, actualiza la CRL y genera la nueva firma criptográfica."""
    pub_pem = key_file.read_bytes()
    root_priv_pem = root_key.read_bytes()
    fingerprint = calcular_fingerprint_clave(pub_pem)

    crl = agregar_revocacion_a_crl(
        trust_dir=trust_dir,
        key_id=key_id,
        fingerprint=fingerprint,
        motivo=reason,
        root_priv_pem=root_priv_pem,
        replacement_key_id=replacement_id,
    )

    if json_output:
        _emitir_json("trust revoke", {"key_id": key_id, "fingerprint": fingerprint, "motivo": reason,
                                      "total_revocadas": len(crl.revoked_keys)})
        return

    console.print(Panel(
        f"[bold red]✓ Clave revocada exitosamente y CRL actualizada:[/bold red]\n\n"
        f"• **Key ID:** `{key_id}`\n"
        f"• **Fingerprint SHA-256:** `{fingerprint}`\n"
        f"• **Motivo:** `{reason}`\n"
        f"• **Total Claves Revocadas en CRL:** {len(crl.revoked_keys)}\n\n"
        "[yellow]Recordá hacer commit y push de 'crl.json' y 'crl.json.sig' al repositorio de GitHub.[/yellow]",
        title="[bold red]Keymaker Key Revocation[/bold red]",
        border_style="red",
    ))


@trust_app.command("check-revocation")
def cmd_trust_check_revocation(
    key_id: Optional[str] = typer.Option(None, "--key-id", "-i", help="ID de la clave a verificar."),
    key_file: Optional[Path] = typer.Option(None, "--key-file", "-f", help="Archivo de clave pública (.pub)."),
    trust_dir: Path = typer.Option(DEFAULT_TRUST_DIR, "--trust-dir", "-t", help="Directorio del Trust Store."),
    json_output: bool = typer.Option(False, "--json", help=JSON_OPT),
) -> None:
    """Comprueba si una clave pública figura como revocada en la CRL oficial."""
    if not key_id and not key_file:
        err_console.print("[bold red]Debés especificar al menos --key-id o --key-file.[/bold red]")
        raise typer.Exit(code=1)

    pub_pem = key_file.read_bytes() if key_file and key_file.exists() else None
    target_id = key_id or (key_file.stem if key_file else "desconocida")

    store = TrustStore(trust_dir)
    revocada, rec = store.esta_revocada(key_id=target_id, public_key_pem=pub_pem)

    if json_output:
        datos = {"key_id": target_id, "revocada": bool(revocada and rec)}
        if revocada and rec:
            datos.update({"fecha_revocacion": rec.revoked_at_utc, "motivo": rec.reason,
                          "reemplazo": rec.replacement_key_id})
        _emitir_json("trust check-revocation", datos)
        raise typer.Exit(code=1 if revocada and rec else 0)

    if revocada and rec:
        console.print(Panel(
            f"[bold red]❌ ATENCIÓN: CLAVE REVOCADA[/bold red]\n\n"
            f"• **Key ID:** `{rec.key_id}`\n"
            f"• **Fecha de Revocación:** `{rec.revoked_at_utc}`\n"
            f"• **Motivo:** `{rec.reason}`\n"
            f"• **Clave de Reemplazo:** `{rec.replacement_key_id or 'Ninguna'}`",
            title="[bold red]Estado: REVOCADA[/bold red]",
            border_style="red",
        ))
        raise typer.Exit(code=1)
    else:
        console.print(f"[bold green]✓ Clave '{target_id}' NO está revocada.[/bold green] (Estado activo en Trust Store).")
