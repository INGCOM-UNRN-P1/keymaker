---
title: "Guía de Extensión y Creación de Plugins: keymaker"
subtitle: "Manual de integración, desarrollo de extensiones y uso de la API Python de keymaker"
author: "Cátedra de Algoritmos y Programación"
date: "2026-08-31"
---

(manual-keymaker-plugins)=
# Guía de Extensión y Plugins: keymaker

````{abstract}
Esta guía técnica detalla cómo utilizar la API programática de **`keymaker`** e integrar sus capacidades criptográficas (cifrado AES-GCM, verificación de firmas Ed25519 y Time-Lock) en scripts de corrección masiva de Dredd o pipelines de CI/CD.
````

---

(manual-keymaker-plugins-api)=
## 1. Conexión Programática mediante la API Python

Podés importar y utilizar las funciones criptográficas de `keymaker` directamente en tus herramientas:

````{{code-block}} python
:linenos:
from pathlib import Path
from keymaker.core.bundle import crear_bundle_cifrado, desempaquetar_bundle_cifrado
from keymaker.core.crypto import generar_par_claves_ed25519

# 1. Generar claves en memoria
priv_pem, pub_pem = generar_par_claves_ed25519()

# 2. Empaquetar y cifrar un enunciado
meta = crear_bundle_cifrado(
    contenido_bytes=b"Contenido secreto del examen",
    passphrase="ClaveDocenteSegura2026!",
    output_path=Path("examen.ripkg.enc"),
    time_lock_utc="2026-09-15T09:00:00Z",
    private_key_pem=priv_pem,
)

# 3. Desempaquetar y validar firma
payload_descifrado, metadata_verificada = desempaquetar_bundle_cifrado(
    bundle_path=Path("examen.ripkg.enc"),
    passphrase="ClaveDocenteSegura2026!",
    public_key_pem=pub_pem,
    ignore_time_lock=True, # Modo docente
)

print(f"Checksum verificado: {metadata_verificada['checksum_sha256']}")
````

---

(manual-keymaker-plugins-dredd)=
## 2. Plugin de Ingesta Segura para Dredd

Para integrar el descifrado automático de exámenes en el autograder masivo de `dredd`, creá un hook de pre-evaluación:

````{{code-block}} python
:linenos:
# dredd_keymaker_hook.py
from pathlib import Path
from keymaker.core.bundle import desempaquetar_bundle_cifrado, extraer_payload_a_directorio

class KeymakerIngestHook:
    """Hook de Dredd para descifrar paquetes .ripkg.enc antes de evaluar."""
    name = "keymaker_ingest"

    def pre_eval(self, submission_dir: Path, config: dict):
        encrypted_pkg = submission_dir / "entrega.ripkg.enc"
        if encrypted_pkg.exists():
            passphrase = config.get("exam_passphrase", "")
            pub_key = config.get("catedra_pub_key_bytes")
            
            plaintext, meta = desempaquetar_bundle_cifrado(
                bundle_path=encrypted_pkg,
                passphrase=passphrase,
                public_key_pem=pub_key,
            )
            extraer_payload_a_directorio(plaintext, submission_dir / "src")
````

---

(manual-keymaker-plugins-ejercicios)=
## 3. Ejercicios Prácticos de Integración

````{{exercise}} Ejercicio 1: Script de Firma en Lote
Escribir un script en Python que recorra todos los enunciados `.yaml` de una carpeta y genere los archivos de firma digital `.sig` correspondientes usando `keymaker.core.crypto.firmar_mensaje_ed25519`.
````

````{{solution}} Ejercicio 1
```python
from pathlib import Path
from keymaker.core.crypto import firmar_mensaje_ed25519

def firmar_banco(directorio: Path, clave_privada_path: Path):
    priv_pem = clave_privada_path.read_bytes()
    for yaml_file in directorio.glob("**/*.yaml"):
        sig = firmar_mensaje_ed25519(yaml_file.read_bytes(), priv_pem)
        yaml_file.with_suffix(".yaml.sig").write_bytes(sig)
```
````
