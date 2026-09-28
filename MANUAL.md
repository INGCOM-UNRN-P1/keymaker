# Manual de Uso y Referencia Técnica: keymaker

> **KEYMAKER** — Gestor de cifrado autenticado, integridad y desbloqueo temporal para paquetes de examen (.ripkg.enc)
> **Versión:** `0.1.0` · **CLI principal:** `keymaker` · **Plugin Ripley:** `keymaker`

---

## 1. Arquitectura y Propósito Pedagógico

`keymaker` forma parte del ecosistema de herramientas de la cátedra de Programación 1 (UNRN). Su objetivo central es resolver de forma modular, determinista y automatizada las tareas asociadas a su dominio específico dentro del ciclo de desarrollo, evaluación y aprendizaje de software en C.

### Alcance Funcional (Qué cubre)
- Motor de seguridad criptográfica y gestión de integridad para paquetes docentes de examen.
- Cifrado simétrico autenticado (AES-256-GCM / ChaCha20-Poly1305) para bundles de examen empaquetados (`.ripkg.enc`).
- Firma digital asimétrica y verificación de autenticidad mediante claves Ed25519 de cátedra.
- Desbloqueo temporal (Time-Lock) **disuasivo**: la hora UTC se compara con el reloj de la máquina que abre el paquete; quien tenga la frase de paso puede adelantarlo o descifrar el bundle con otra herramienta. Para que no se abra antes de hora, la frase de paso se distribuye recién al inicio (o se reparte con `keymaker split-secret`).
- División y recuperación de secretos docentes mediante esquema de Shamir (Secret Sharing $k$ de $n$ en GF(256)).
- Auditoría de entropía de contraseñas de examen y verificación de claves contra repositorio público de confianza (Trust Store / CRL).

### Límites de Responsabilidad y Delegación (Qué no cubre)
- Redacción y maquetación de exámenes (delegado a `alucard` y `deckard`).
- Calificación de estudiantes ni cálculo de notas (delegado a `dredd`).
- Análisis de seguridad en código fuente C (delegado a `kaneda`).

### Principios de Diseño
- **Enfoque Pedagógico:** Diagnósticos y mensajes en español rioplatense orientados a facilitar la comprensión de errores conceptuales.
- **Salida Estructurada Dual:** Soporte nativo para visualización enriquecida en terminal (Rich) y salida parseable para orquestadores (`--json`).
- **Integración Contractual:** Capacidad de emitir secciones de reporte para `dredd` (`dredd-section`) y actuar como satélite orquestado por `ripley`.
- **Idempotencia y Robustez:** Validación de precondiciones y comandos de autodiagnóstico (`doctor`) para verificación del entorno.

---

## 2. Instalación y Requisitos

### Requisitos del Sistema
- **Python:** `>= 3.10` (recomendado Python 3.11 o 3.12).
- **Gestor de paquetes:** [`uv`](https://github.com/astral-sh/uv) (entorno estándar de cátedra).
- **Toolchain C (si aplica):** GCC / Clang, Make, GDB y bibliotecas estándar de desarrollo.

### Instalación en el Entorno de Usuario
Para instalar la herramienta de forma global y aislada en el sistema mediante `uv tool`:
```bash
uv tool install --editable /home/mrtin/dev/tools/keymaker
```

### Verificación de Instalación
Ejecutá el comando `doctor` para constatar que todas las dependencias y binarios requeridos estén presentes y operativos:
```bash
keymaker doctor
```

---

## 3. Guía Integral de Comandos (CLI)

| Comando | Descripción Breve |
| :--- | :--- |
| [`keymaker encrypt`](#encrypt) | Empaqueta y cifra un examen o pauta en un bundle autenticado (.ripkg.enc). |
| [`keymaker pack`](#pack) | Empaqueta y cifra un examen o pauta en un bundle autenticado (.ripkg.enc). |
| [`keymaker inspect`](#inspect) | Informa si un archivo está realmente cifrado por keymaker o viaja en claro. |
| [`keymaker decrypt`](#decrypt) | Descifra, verifica la integridad y extrae el contenido de un bundle (.ripkg.enc). |
| [`keymaker unpack`](#unpack) | Descifra, verifica la integridad y extrae el contenido de un bundle (.ripkg.enc). |
| [`keymaker gen-keys`](#genkeys) | Genera un nuevo par de claves asimétricas Ed25519 para firma digital de exámenes. |
| [`keymaker sign`](#sign) | Firma un archivo con una clave privada Ed25519. |
| [`keymaker verify`](#verify) | Verifica la firma digital Ed25519 de un archivo consultando el Trust Store. |
| [`keymaker split-secret`](#splitsecret) | Divide un secreto docente en N partes usando el esquema de Shamir (k de n). |
| [`keymaker combine-shares`](#combineshares) | Reconstruye un secreto a partir de K partes de Shamir. |
| [`keymaker audit-passphrase`](#auditpassphrase) | Audita la entropía y robustez criptográfica de una frase de paso para exámenes. |
| [`keymaker checksum`](#checksum) | Calcula el checksum SHA-256 de un archivo para control de integridad. |
| [`keymaker doctor`](#doctor) | Ejecuta el diagnóstico integral del subsistema criptográfico. |

### `keymaker encrypt`

Empaqueta y cifra un examen o pauta en un bundle autenticado (.ripkg.enc).

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `origen` | `Path` | Archivo o directorio a empaquetar y cifrar. |
| `output` | `Path` | Ruta del archivo de salida (.ripkg.enc). |
| `passphrase` | `str` | Frase de paso para cifrado. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--time-lock`, `-t` | `Optional[str]` | `None` | Fecha/hora UTC de desbloqueo (ej: 2026-09-15T09:00:00Z). |
| `--legajo`, `-l` | `Optional[str]` | `None` | Legajo de estudiante para derivación HKDF. |
| `--sign-key`, `-s` | `Optional[Path]` | `None` | Clave privada Ed25519 (.key) para firmar digitalmente. |
| `--json` | `bool` | `False` | Emitir el resultado en JSON versionado (schema_version). |

#### Ejemplo de Invocación
```bash
keymaker encrypt <origen> <output> <passphrase>
```

### `keymaker pack`

Empaqueta y cifra un examen o pauta en un bundle autenticado (.ripkg.enc).

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `origen` | `Path` | Archivo o directorio a empaquetar y cifrar. |
| `output` | `Path` | Ruta del archivo de salida (.ripkg.enc). |
| `passphrase` | `str` | Frase de paso para cifrado. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--time-lock`, `-t` | `Optional[str]` | `None` | Fecha/hora UTC de desbloqueo (ej: 2026-09-15T09:00:00Z). |
| `--legajo`, `-l` | `Optional[str]` | `None` | Legajo de estudiante para derivación HKDF. |
| `--sign-key`, `-s` | `Optional[Path]` | `None` | Clave privada Ed25519 (.key) para firmar digitalmente. |
| `--json` | `bool` | `False` | Emitir el resultado en JSON versionado (schema_version). |

#### Ejemplo de Invocación
```bash
keymaker pack <origen> <output> <passphrase>
```

### `keymaker inspect`

Informa si un archivo está realmente cifrado por keymaker o viaja en claro.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `archivo` | `Path` | Archivo a inspeccionar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Emitir el resultado en JSON. |

#### Ejemplo de Invocación
```bash
keymaker inspect <archivo>
```

### `keymaker decrypt`

Descifra, verifica la integridad y extrae el contenido de un bundle (.ripkg.enc).

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `bundle` | `Path` | Ruta al archivo cifrado (.ripkg.enc). |
| `passphrase` | `str` | Frase de paso para descifrado. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--output`, `-o` | `Path` | `desempaquetado` | Directorio destino para extraer el contenido. |
| `--legajo`, `-l` | `Optional[str]` | `None` | Legajo de estudiante para derivación HKDF. |
| `--verify-key`, `-v` | `Optional[Path]` | `None` | Clave pública Ed25519 (.pub) para verificar la firma. |
| `--force`, `-f` | `bool` | `False` | Forzar desbloqueo docente omitiendo el Time-Lock. |
| `--trust-dir` | `Path` | `/home/mrtin/.keymaker/trust` | Directorio del Trust Store para verificar revocaciones. |
| `--json` | `bool` | `False` | Emitir el resultado en JSON versionado (schema_version). |

#### Ejemplo de Invocación
```bash
keymaker decrypt <bundle> <passphrase>
```

### `keymaker unpack`

Descifra, verifica la integridad y extrae el contenido de un bundle (.ripkg.enc).

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `bundle` | `Path` | Ruta al archivo cifrado (.ripkg.enc). |
| `passphrase` | `str` | Frase de paso para descifrado. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--output`, `-o` | `Path` | `desempaquetado` | Directorio destino para extraer el contenido. |
| `--legajo`, `-l` | `Optional[str]` | `None` | Legajo de estudiante para derivación HKDF. |
| `--verify-key`, `-v` | `Optional[Path]` | `None` | Clave pública Ed25519 (.pub) para verificar la firma. |
| `--force`, `-f` | `bool` | `False` | Forzar desbloqueo docente omitiendo el Time-Lock. |
| `--trust-dir` | `Path` | `/home/mrtin/.keymaker/trust` | Directorio del Trust Store para verificar revocaciones. |
| `--json` | `bool` | `False` | Emitir el resultado en JSON versionado (schema_version). |

#### Ejemplo de Invocación
```bash
keymaker unpack <bundle> <passphrase>
```

### `keymaker gen-keys`

Genera un nuevo par de claves asimétricas Ed25519 para firma digital de exámenes.

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--prefix`, `-p` | `str` | `catedra` | Prefijo de los archivos de clave generados. |
| `--output-dir`, `-o` | `Path` | `.` | Directorio donde guardar las claves. |
| `--json` | `bool` | `False` | Emitir el resultado en JSON versionado (schema_version). |

#### Ejemplo de Invocación
```bash
keymaker gen-keys
```

### `keymaker sign`

Firma un archivo con una clave privada Ed25519.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `archivo` | `Path` | Archivo a firmar. |
| `key_file` | `Path` | Ruta a la clave privada Ed25519 (.key). |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--output`, `-o` | `Optional[Path]` | `None` | Archivo de firma de salida (.sig). |
| `--json` | `bool` | `False` | Emitir el resultado en JSON versionado (schema_version). |

#### Ejemplo de Invocación
```bash
keymaker sign <archivo> <key_file>
```

### `keymaker verify`

Verifica la firma digital Ed25519 de un archivo consultando el Trust Store.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `archivo` | `Path` | Archivo a verificar. |
| `sig_file` | `Path` | Archivo de firma (.sig). |
| `pub_file` | `Path` | Clave pública Ed25519 (.pub). |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--trust-dir` | `Path` | `/home/mrtin/.keymaker/trust` | Directorio del Trust Store para verificar revocaciones. |
| `--json` | `bool` | `False` | Emitir el resultado en JSON versionado (schema_version). |

#### Ejemplo de Invocación
```bash
keymaker verify <archivo> <sig_file> <pub_file>
```

### `keymaker split-secret`

Divide un secreto docente en N partes usando el esquema de Shamir (k de n).

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `secreto` | `str` | Texto o frase de paso a dividir. |
| `k` | `int` | Umbral mínimo de partes requeridas para descifrar. |
| `n` | `int` | Cantidad total de partes a generar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Emitir salida en formato JSON. |

#### Ejemplo de Invocación
```bash
keymaker split-secret <secreto> <k> <n>
```

### `keymaker combine-shares`

Reconstruye un secreto a partir de K partes de Shamir.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `shares` | `List[str]` | Partes en formato 'indice:share_b64' (ej: '1:Ag4F...' '3:Bw8Z...'). |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Emitir el resultado en JSON versionado (schema_version). |

#### Ejemplo de Invocación
```bash
keymaker combine-shares <shares>
```

### `keymaker audit-passphrase`

Audita la entropía y robustez criptográfica de una frase de paso para exámenes.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `frase` | `str` | Frase de paso a auditar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Emitir reporte en JSON. |

#### Ejemplo de Invocación
```bash
keymaker audit-passphrase <frase>
```

### `keymaker checksum`

Calcula el checksum SHA-256 de un archivo para control de integridad.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `archivo` | `Path` | Archivo a calcular hash SHA-256. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Emitir el resultado en JSON versionado (schema_version). |

#### Ejemplo de Invocación
```bash
keymaker checksum <archivo>
```

### `keymaker doctor`

Ejecuta el diagnóstico integral del subsistema criptográfico.

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Emitir el resultado en JSON versionado (schema_version). |

#### Ejemplo de Invocación
```bash
keymaker doctor
```

---

## 4. Formatos de Salida e Integración con el Ecosistema

### Modo Interactivo / Terminal (Rich)
Por defecto, la herramienta renderiza paneles, árboles y tablas estilizadas para facilitar la lectura del estudiante y docente en terminales modernas con soporte ANSI.

### Modo Estructurado JSON (`--json`)
Para integración con pipelines de CI/CD, scripts de automatización u orquestadores externos, la opción `--json` emite un documento JSON estricto por la salida estándar (`stdout`), dirigiendo cualquier mensaje de logging a `stderr`:
```bash
keymaker encrypt --json
```

### Integración con Dredd (`dredd-section`)
Cuando la herramienta genera reportes de evaluación para entregas de alumnos, produce una sección Markdown estandarizada conforme al contrato de integración de Dredd (v1.0.0):
```markdown
<!-- dredd-section: keymaker, tool=keymaker, version=0.1.0, status=ok -->
```
Este encabezado garantiza la agregación determinista de los hallazgos en la rúbrica docente.

### Integración con Ripley
`keymaker` está registrada en el catálogo de plugins satélites de Ripley (`SATELLITE_CATALOG`). Puede invocarse directamente a través del motor de evaluación de Ripley configurando el análisis en `ripley.toml`.

---

## 5. Diagnóstico y Códigos de Salida

### Códigos de Retorno (`exit code`)
| Código | Significado |
| :---: | :--- |
| `0` | Ejecución exitosa sin hallazgos críticos ni errores de sintaxis. |
| `1` | Hallazgos pedagógicos detectados, infracción de reglas o advertencias activas. |
| `2` | Error de sintaxis en argumentos CLI o archivo fuente no encontrado. |
| `>2` | Error no recuperable del sistema, fallo de memoria o excepción interna. |

### Diagnóstico del Entorno (`doctor`)
Ante comportamientos inesperados, verificá el estado operativo con:
```bash
keymaker doctor
```
Comprueba la presencia de las dependencias requeridas y la integridad de los componentes del paquete.