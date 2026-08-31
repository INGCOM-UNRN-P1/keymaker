# Keymaker 🔐

Gestor de cifrado simétrico autenticado (AES-256-GCM / ChaCha20-Poly1305), firmas digitales Ed25519, Time-Lock y división de secretos de Shamir para paquetes de examen en C.

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
