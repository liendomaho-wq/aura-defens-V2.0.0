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

## Motor LLM (superficie añadida en v1.0.0-llm)

El LLM es un componente **no confiable** por diseño. En alcance:

- Conseguir que el modelo despache un `toolId` fuera de `AuraToolCatalog.allowedIds`
- Conseguir que un `target` generado por el modelo llegue a `su -c` sin pasar por `RootCommandPolicy`
- Bypass de `TargetValidator` (host, IP, puerto o texto libre)
- Exfiltración de telemetría identificable pese a `TelemetryRedactor` (IPs privadas, MACs, correos,
  JWT, tokens)
- Prompt injection en el texto del usuario que altere el comportamiento de Aura
- Fuga de la API key desde `EncryptedSharedPreferences`, logs o backups

Fuera de alcance:

- Que el modelo alucine texto en el informe: el riesgo está acotado a la redacción, no a la ejecución
- Que un proveedor externo registre lo que recibe (se avisa en la app antes de activarlo)
