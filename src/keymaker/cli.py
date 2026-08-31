"""CLI principal de Keymaker — Gestor de cifrado e integridad de paquetes de examen."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from keymaker import __version__
from keymaker.core.bundle import (
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

app = typer.Typer(
    name="keymaker",
    help="🔐 Keymaker — Gestor de cifrado simétrico autenticado (AES-GCM), firmas Ed25519 y Time-Lock para exámenes.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]keymaker[/bold cyan] versión [green]{__version__}[/green]")
        raise typer.Exit(code=0)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "-v",
        "--version",
        help="Muestra la versión de Keymaker y finaliza.",
        callback=version_callback,
        is_eager=True,
    ),
):
    pass


@app.command("pack")
@app.command("encrypt")
def cmd_pack(
    origen: Path = typer.Argument(..., help="Archivo o directorio a empaquetar y cifrar.", exists=True),
    output: Path = typer.Option(..., "--output", "-o", help="Ruta del archivo de salida (.ripkg.enc)."),
    passphrase: str = typer.Option(..., "--passphrase", "-p", prompt=True, hide_input=True, help="Frase de paso para cifrado."),
    time_lock: Optional[str] = typer.Option(None, "--time-lock", "-t", help="Fecha/hora UTC de desbloqueo (ej: 2026-09-15T09:00:00Z)."),
    legajo: Optional[str] = typer.Option(None, "--legajo", "-l", help="Legajo de estudiante para derivación HKDF."),
    signing_key: Optional[Path] = typer.Option(None, "--sign-key", "-s", help="Clave privada Ed25519 (.key) para firmar digitalmente."),
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


@app.command("unpack")
@app.command("decrypt")
def cmd_unpack(
    bundle: Path = typer.Argument(..., help="Ruta al archivo cifrado (.ripkg.enc).", exists=True),
    output_dir: Path = typer.Option(Path("./desempaquetado"), "--output", "-o", help="Directorio destino para extraer el contenido."),
    passphrase: str = typer.Option(..., "--passphrase", "-p", prompt=True, hide_input=True, help="Frase de paso para descifrado."),
    legajo: Optional[str] = typer.Option(None, "--legajo", "-l", help="Legajo de estudiante para derivación HKDF."),
    verify_key: Optional[Path] = typer.Option(None, "--verify-key", "-v", help="Clave pública Ed25519 (.pub) para verificar la firma."),
    force_unlock: bool = typer.Option(False, "--force", "-f", help="Forzar desbloqueo docente omitiendo el Time-Lock."),
) -> None:
    """Descifra, verifica la integridad y extrae el contenido de un bundle (.ripkg.enc)."""
    pub_pem: Optional[bytes] = None
    if verify_key:
        if not verify_key.exists():
            err_console.print(f"[bold red]No existe la clave pública: {verify_key}[/bold red]")
            raise typer.Exit(code=1)
        pub_pem = verify_key.read_bytes()

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
) -> None:
    """Genera un nuevo par de claves asimétricas Ed25519 para firma digital de exámenes."""
    priv_pem, pub_pem = generar_par_claves_ed25519()

    out_dir.mkdir(parents=True, exist_ok=True)
    priv_file = out_dir / f"{prefix}.key"
    pub_file = out_dir / f"{prefix}.pub"

    priv_file.write_bytes(priv_pem)
    pub_file.write_bytes(pub_pem)
    # Permisos seguros para la clave privada (chmod 600)
    try:
        os.chmod(priv_file, 0o600)
    except Exception:
        pass

    console.print(f"[bold green]✓ Par de claves Ed25519 generado exitosamente:[/bold green]")
    console.print(f"  • [bold]Clave Privada (Firma):[/bold] [cyan]{priv_file}[/cyan] (chmod 600)")
    console.print(f"  • [bold]Clave Pública (Verificación):[/bold] [cyan]{pub_file}[/cyan]")


@app.command("sign")
def cmd_sign(
    archivo: Path = typer.Argument(..., help="Archivo a firmar.", exists=True),
    key_file: Path = typer.Option(..., "--key", "-k", help="Ruta a la clave privada Ed25519 (.key).", exists=True),
    sig_output: Optional[Path] = typer.Option(None, "--output", "-o", help="Archivo de firma de salida (.sig)."),
) -> None:
    """Firma un archivo con una clave privada Ed25519."""
    data = archivo.read_bytes()
    priv_pem = key_file.read_bytes()
    sig = firmar_mensaje_ed25519(data, priv_pem)

    out_path = sig_output or archivo.with_suffix(archivo.suffix + ".sig")
    out_path.write_bytes(sig)
    console.print(f"[bold green]✓ Firma digital generada en:[/bold green] [cyan]{out_path}[/cyan]")


@app.command("verify")
def cmd_verify(
    archivo: Path = typer.Argument(..., help="Archivo a verificar.", exists=True),
    sig_file: Path = typer.Option(..., "--sig", "-s", help="Archivo de firma (.sig).", exists=True),
    pub_file: Path = typer.Option(..., "--pub", "-p", help="Clave pública Ed25519 (.pub).", exists=True),
) -> None:
    """Verifica la firma digital Ed25519 de un archivo."""
    data = archivo.read_bytes()
    sig = sig_file.read_bytes()
    pub_pem = pub_file.read_bytes()

    if verificar_firma_ed25519(data, sig, pub_pem):
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
        print(json.dumps({"k": k, "n": n, "shares": shares_formatted}, indent=2))
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

    console.print(f"\n[bold green]✓ Secreto reconstruido con éxito:[/bold green] [bold cyan]{secreto_str}[/bold cyan]\n")


@app.command("audit-passphrase")
def cmd_audit_passphrase(
    frase: str = typer.Argument(..., help="Frase de paso a auditar."),
    json_output: bool = typer.Option(False, "--json", help="Emitir reporte en JSON."),
) -> None:
    """Audita la entropía y robustez criptográfica de una frase de paso para exámenes."""
    reporte = auditar_frase_paso(frase)

    if json_output:
        print(json.dumps(reporte, indent=2, ensure_ascii=False))
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
) -> None:
    """Calcula el checksum SHA-256 de un archivo para control de integridad."""
    h = calcular_sha256_archivo(str(archivo))
    console.print(f"[bold white]{h}[/bold white]  [cyan]{archivo}[/cyan]")


@app.command("doctor")
def cmd_doctor() -> None:
    """Ejecuta el diagnóstico integral del subsistema criptográfico."""
    diag = ejecutar_diagnostico_doctor(console=console)
    if not diag["todo_ok"]:
        raise typer.Exit(code=1)
