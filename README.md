# Keymaker 🔐

Gestor de cifrado simétrico autenticado (AES-256-GCM / ChaCha20-Poly1305), firmas digitales Ed25519, Time-Lock y división de secretos de Shamir para paquetes de examen en C.

---

## 🎯 Alcance

### Qué cubre
- Motor de seguridad criptográfica y gestión de integridad para paquetes docentes de examen.
- Cifrado simétrico autenticado (AES-256-GCM / ChaCha20-Poly1305) para bundles de examen empaquetados (`.ripkg.enc`).
- Firma digital asimétrica y verificación de autenticidad mediante claves Ed25519 de cátedra.
- Desbloqueo temporal sincronizado (Time-Lock) con validación estricta de horario UTC para apertura de evaluaciones.
- División y recuperación de secretos docentes mediante esquema de Shamir (Secret Sharing $k$ de $n$ en GF(256)).
- Auditoría de entropía de contraseñas de examen y verificación de claves contra repositorio público de confianza (Trust Store / CRL).

### Qué no cubre (Límites y Delegación)
- Redacción y maquetación de exámenes (delegado a `alucard` y `deckard`).
- Calificación de estudiantes ni cálculo de notas (delegado a `dredd`).
- Análisis de seguridad en código fuente C (delegado a `kaneda`).

---

## 📋 Requisitos

### Requisitos de Sistema y Entorno
- Multiplataforma. Python >= 3.10.

### Dependencias Externas y Binarios
- `openssl` (opcional; utiliza backend criptográfico puro en Python vía `cryptography`).

### Integración en el Ecosistema
- CLI `keymaker`. Subcomando `keymaker doctor`. Integrado con `alucard` y `dredd`.

---

## Características

- **Cifrado Autenticado de Exámenes**: Empaquetado seguro en formato `.ripkg.enc`.
- **Desbloqueo Temporal (Time-Lock)**: Impide el acceso al contenido antes de la hora oficial del examen.
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

# Empaquetar y cifrar un examen con Time-Lock
keymaker pack ./parcial_tema_1 -o parcial1.ripkg.enc -t "2026-09-15T09:00:00Z"
```
