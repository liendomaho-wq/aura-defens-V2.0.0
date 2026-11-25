# Política de seguridad

Aura Mobile Defense ejecuta inspecciones con privilegios elevados en el dispositivo del usuario, así
que los fallos de seguridad se tratan como prioritarios.

## Reportar una vulnerabilidad

No abras un issue público. Usa **GitHub Security Advisories**:
`Security → Advisories → New draft security advisory` en este repositorio, o escribe al mantenedor
indicado en el perfil del repo.

Incluye, si es posible:

- Versión / commit afectado
- Pasos de reproducción
- Impacto esperado (fuga de datos, ejecución de comandos, bypass del firewall…)
- Logcat o captura de la telemetría de Aura (revisa que no contenga datos personales)

## Alcance

En alcance:

- Bypass de `RootCommandPolicy` (cualquier entrada del chat que acabe en `su -c` sin pasar la lista blanca)
- Evasión de reglas del firewall/VPN (`VpnFirewallManager`, `AuraLocalVpnService`, `PacketCodec`)
- Fuga de la base forense por backup, exportación o logs
- Vulnerabilidades en el manejo de certificados TLS de los motores de auditoría

Fuera de alcance:

- Falta de cifrado en reposo de la base de datos (limitación conocida, ver roadmap del README)
- Requerir root para funcionalidades que el README ya marca como limitadas sin root
- Ataques que requieran un dispositivo ya comprometido con root y hooks activos

## Compromiso

- Acuse de recibo en 72 h
- Evaluación y plan de corrección en 7 días
- Crédito público en el advisory si lo deseas
