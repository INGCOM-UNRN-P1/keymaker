# Keymaker 🔐

> 📖 **Manual de Usuario:** Para una guía exhaustiva de comandos, banderas, arquitectura y ejemplos, consultá el [Manual de Uso](MANUAL.md).

Gestor de cifrado simétrico autenticado (AES-256-GCM / ChaCha20-Poly1305), firmas digitales Ed25519, Time-Lock y división de secretos de Shamir para paquetes de examen en C.

---

## 🎯 Alcance

### Qué cubre
- Motor de seguridad criptográfica y gestión de integridad para paquetes docentes de examen.
- Cifrado simétrico autenticado (AES-256-GCM / ChaCha20-Poly1305) para bundles de examen empaquetados (`.ripkg.enc`).
- Firma digital asimétrica y verificación de autenticidad mediante claves Ed25519 de cátedra.
- Desbloqueo temporal (Time-Lock) **disuasivo**: la hora UTC se compara con el reloj de la máquina que abre el paquete (ver «Límites del Time-Lock»).
- División y recuperación de secretos docentes mediante esquema de Shamir (Secret Sharing $k$ de $n$ en GF(256)).
- Auditoría de entropía de contraseñas de examen y verificación de claves contra repositorio público de confianza (Trust Store / CRL).

### Qué no cubre (Límites y Delegación)
- Redacción y maquetación de exámenes (delegado a `alucard` y `deckard`).
- Calificación de estudiantes ni cálculo de notas (delegado a `dredd`).
- Análisis de seguridad en código fuente C (delegado a `kaneda`).

---

## ⏱ Límites del Time-Lock

El Time-Lock compara la hora de apertura con el **reloj de la máquina** que abre el
paquete. Quien tenga la frase de paso puede adelantar ese reloj o descifrar el bundle
(AES-GCM estándar) con otra herramienta, así que el Time-Lock **disuade pero no impide**
abrir un examen antes de hora (N-KEYMAKER-01). Para que no se pueda abrir antes:

- distribuí la frase de paso recién a la hora de inicio, o
- repartila entre docentes con `keymaker split-secret` y reconstruila con `keymaker combine-shares` al empezar.

`keymaker pack --time-lock` lo recuerda al empaquetar (y en `--json`, campo `advertencia_time_lock`).

---

## 📋 Requisitos

### Requisitos de Sistema y Entorno
- Multiplataforma. Python >= 3.10.

### Dependencias Externas y Binarios
- `openssl` (opcional; utiliza backend criptográfico puro en Python vía `cryptography`).

### Integración en el Ecosistema
- CLI `keymaker`. Subcomando `keymaker doctor`. Utilidad criptográfica independiente para generación, verificación y custodia de paquetes de evaluación.

---

## Características

- **Cifrado Autenticado de Exámenes**: Empaquetado seguro en formato `.ripkg.enc`.
- **Desbloqueo Temporal (Time-Lock)**: Disuade de abrir el contenido antes de la hora oficial del examen (con bypass auditado mediante clave docente autorizada). No lo impide: ver «Límites del Time-Lock».
- **Derivación de Claves por Legajo (HKDF-SHA256)**: Paquetes individualizados por estudiante.
- **División de Secretos de Shamir ($k$ de $n$)**: Requiere el quórum de $k$ docentes para descifrar pautas sensibles.
- **Firmas Digitales Asimétricas (Ed25519)**: Certificación de autoría e integridad de enunciados y starter kits.
- **Auditor de Entropía de Contraseñas**: Validación de frases de paso para evitar claves débiles.

## Instalación y Uso Rápido

```bash
# Instalación con uv
uv tool install . --editable

# Diagnóstico de capacidades criptográficas
keymaker doctor

# Generar par de claves Ed25519
keymaker gen-keys -o clave_docente

# Empaquetar y cifrar un examen con Time-Lock (disuasivo: ver «Límites del Time-Lock»)
keymaker pack ./parcial_tema_1 -o parcial1.ripkg.enc -t "2026-09-15T09:00:00Z"

# Desempaquetar y descifrar bundle
keymaker unpack parcial1.ripkg.enc -o ./examen_descifrado

# Firmar digitalmente y verificar integridad de un archivo
keymaker sign enunciado.pdf -k clave_docente.ed25519.priv
keymaker verify enunciado.pdf enunciado.pdf.sig -k clave_docente.ed25519.pub

# Dividir un secreto en 5 partes (quórum de 3) y reconstruirlo
keymaker split-secret "ContraseñaSuperSecreta" -n 5 -k 3
keymaker combine-shares parte1.json parte2.json parte3.json

# Auditar entropía de frase de paso
keymaker audit-passphrase "AlgoritmosYProgramacion2026"

# Gestión de repositorio de confianza (Trust Store / CRL)
keymaker trust list
```
