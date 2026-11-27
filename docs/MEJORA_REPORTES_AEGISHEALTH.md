# Mejora de los reportes de AegisHealth-CTI — Ejecutivo (no técnico) y Técnico (F-11)
**Para:** Rol 3 (generador de PDF y prompts de Ollama) y Rol 5 (redacción y QA) · **De:** Rol 2 · **Viernes 27-nov-2026, 10:20**
**Entrega 13:30.** Todo lo que sigue se puede aplicar en 1 o 2 horas.

---

## 0. El principio que falta en los dos reportes: "lo más importante primero"

Hoy los dos reportes **empiezan por el contexto y terminan con la conclusión**. Un directivo lee la primera mitad de la primera página y decide. Un analista busca primero qué es lo grave y qué tiene que bloquear.

**Regla (pirámide invertida o "BLUF: la conclusión primero"):**
1. **Qué pasó y qué tan grave es** (una o dos frases).
2. **Qué hay que decidir o hacer, y quién** (acciones con plazo).
3. **Las cifras que lo respaldan.**
4. **El detalle**, para quien quiera profundizar.
5. **La metodología y los anexos**, al final.

Prueba rápida: **si alguien lee solo el primer recuadro, ¿sabe qué pasó y qué tiene que hacer?** Hoy, en ninguno de los dos reportes la respuesta es sí.

---

## 1. Diagnóstico del REPORTE EJECUTIVO (Dirección Médica, persona no técnica)

| # | Problema | Gravedad | Corrección |
|---|---|---|---|
| E1 | **Lo más grave está escondido y suavizado.** El 24-oct hubo una **descarga seguida, 30 segundos después, de una conexión hacia un servidor externo**. El reporte lo llama "descarga fuera de turno" y lo pone en el segundo párrafo | 🔴 Crítico | Ponerlo como **primera frase** del reporte, con lenguaje claro: "posible salida de información de salud" |
| E2 | **Un solo semáforo (Amarillo) mezcla todo.** El riesgo principal es de **confidencialidad**, no de continuidad | 🔴 Crítico | **Tres semáforos:** Confidencialidad 🔴 · Integridad 🟠 · Disponibilidad 🟡 (por confirmar) |
| E3 | **No dice qué tiene que decidir el directivo.** El plan es solo "consultar y cotejar" | 🔴 Crítico | Sección **"Lo que necesitamos que usted autorice hoy"**: bloquear salidas no autorizadas, suspender cuentas compartidas y preparar la notificación legal |
| E4 | **Falta la obligación legal clave:** si se confirma una fuga de datos de pacientes, hay que **notificar a la Superintendencia de Protección de Datos Personales en máximo 5 días** (LOPDP art. 43, reformado por la Ley de Ciberseguridad de 2026) | 🔴 Crítico | Agregarlo en las decisiones y en el plan |
| E5 | **"16 cuentas administrativas" no transmite la gravedad.** El dato que impacta es que **11 de esas cuentas las usan decenas o cientos de personas distintas (una, 1.737)**: no se puede saber quién hizo qué | 🟠 Importante | Decirlo así, en palabras simples |
| E6 | **No muestra que el sistema funciona** (5 de 5 ataques detectados, 0 alarmas falsas en 10.000 cuentas normales, aviso 16 días antes) | 🟠 Importante | Una fila de "En números", pequeña y al final |
| E7 | **El plan solo involucra a Talento Humano.** Faltan Sistemas (bloqueo técnico) y el área jurídica o de protección de datos (notificación) | 🟠 Importante | Plan con **responsable y plazo** en cada línea |
| E8 | **Falta el control del documento:** fecha, versión, a quién va dirigido y clasificación (TLP) | 🟡 Menor | Una línea bajo el título |
| E9 | Cita el **art. 25 de la LOPDP** sin verificar | 🟡 Menor | Rol 5: confirmar en el texto oficial el artículo de "categorías especiales". El art. 43 (notificación) está verificado |

---

## 2. REPORTE EJECUTIVO — versión propuesta (texto completo, 1 página)

> Copiar tal cual en la plantilla (o en el prompt de Ollama como "texto obligatorio"). Las cifras salen de `exports_10m` (sección 6).

---
**AegisHealth · Informe ejecutivo para Dirección Médica**
**Riesgo para la información de salud — octubre de 2026 (ejercicio con datos simulados)**
Emitido: 27-nov-2026 · Versión 1.0 · Clasificación: TLP:AMBER (uso interno) · Para: Dirección Médica

**🟥 LO MÁS IMPORTANTE**
1. **Posible salida de información de salud.** El 24 de octubre a las 22:40, una cuenta del sistema médico **descargó información y, 30 segundos después, hubo una conexión hacia un servidor externo** a la institución. Aún no sabemos qué información ni cuánta.
2. **Cuentas compartidas sin control.** 11 de las 16 cuentas administrativas fueron usadas por **decenas o cientos de personas distintas** (una de ellas, por 1.737). Así **no se puede saber quién hizo cada cambio**: activaciones, reactivaciones y cambios de permisos.
3. **No vemos señales de interrupción de la atención** en los registros, pero falta confirmarlo con las jefaturas.

**Estado del riesgo**
| Aspecto | Semáforo | Qué significa |
|---|---|---|
| Confidencialidad (que nadie vea o saque datos de pacientes) | 🔴 Alto | Posible salida de datos el 24-oct |
| Integridad (que los datos y permisos sean correctos) | 🟠 Medio-alto | Cambios masivos de permisos con cuentas compartidas |
| Disponibilidad (que el sistema funcione para atender) | 🟡 Por confirmar | Sin señales de caída en los registros |

**✅ LO QUE NECESITAMOS QUE USTED AUTORICE HOY**
1. **Bloquear las conexiones desde la red clínica hacia internet** que no estén autorizadas. *Responsable: Sistemas · hoy.*
2. **Revisar y suspender las 16 cuentas administrativas compartidas**; cada persona debe usar su propia cuenta. *Responsable: Talento Humano + Sistemas · 48 horas.*
3. **Activar la evaluación legal:** si se confirma que salieron datos de pacientes, la ley exige **notificar a la Superintendencia de Protección de Datos Personales en máximo 5 días** (LOPDP art. 43). *Responsable: Jurídico / Delegado de Protección de Datos · iniciar hoy.*

**Plan de acción**
| Plazo | Acción | Responsable |
|---|---|---|
| **Hoy** | Bloqueo de salidas no autorizadas · preguntar a las jefaturas si hubo demoras en la atención · conservar las evidencias | Sistemas · Dirección Médica |
| **48 horas** | Revisar las 16 cuentas y los permisos cambiados · confirmar si la descarga del 24-oct estaba autorizada y qué contenía | Talento Humano · Jefaturas · Sistemas |
| **1 semana** | Cuentas personales obligatorias · segundo factor de autenticación en cuentas administrativas · decisión final sobre la notificación legal | Sistemas · Jurídico · Dirección Médica |

**En números:** 10 millones de registros revisados · 5 de 5 ataques detectados · 0 de 10.000 cuentas normales marcadas por error · una de las cuentas atacadas ya mostraba señales de riesgo **16 días antes** del ataque.

*Protección de datos: este informe no contiene nombres de pacientes ni de personal. Toda identidad fue reemplazada por códigos (seudonimización).*

---

**Reglas de estilo para este reporte (también para el prompt de Ollama):**
- Prohibido: siglas técnicas (IoC, MITRE, SSH, IP, Sigma, STIX, HMAC). Si hace falta, se dice "conexión", "cuenta", "servidor externo".
- Una idea por frase. Verbos de acción. Cada acción con **responsable y plazo**.
- Diferenciar **hecho** ("se registró") de **pendiente de confirmar** ("aún no sabemos").

---

## 3. Diagnóstico del REPORTE TÉCNICO (F-11, para el analista o el SOC)

| # | Problema | Gravedad | Corrección |
|---|---|---|---|
| T1 | **Empieza por la metodología.** Lo grave (la exfiltración 001 y las acciones) aparece en las páginas 3 y 4 | 🔴 Crítico | Agregar una **"Sección 0 · Resumen de inteligencia"** en la página 1 (texto en la sección 4 de este documento). Las 8 secciones de la ficha se mantienen en su orden para el jurado |
| T2 | **El sello "Pendiente de revisión del Rol 5"** y la mención a "el Rol 1" en el texto | 🔴 Crítico | Quitarlo de la versión final. En lugar de "Rol 1", escribir "el equipo de ingeniería de datos" |
| T3 | **Dice TLP:RED**, pero todos los demás productos (STIX, MISP, Sigma) usan **TLP:AMBER** | 🔴 Crítico | **TLP:AMBER** en todo (RED no permite compartirlo ni siquiera dentro del IESS) |
| T4 | **Las horas llevan "+00:00" (UTC) y el mapa de calor dice "Día (UTC)".** Los registros vienen en **hora local sin zona**: decir que son UTC es incorrecto | 🔴 Crítico | Quitar "+00:00" y escribir "hora local del registro". En la cronología, mostrar también la hora original del sistema médico (10:40:15 → ajustada a 22:40:15) |
| T5 | **Faltan los resultados de ANTICIPACIÓN** (riesgo 16 días antes, alerta en la misma hora, 2 falsas alarmas en 744 h, siguiente fase 4/5): es el diferenciador del proyecto | 🔴 Crítico | Agregarlos en la sección 7 (escenarios) y en el resumen |
| T6 | **Los KPIs de portada no son los importantes:** "1.280 IP sin puntos" es un dato de calidad, no de amenaza | 🟠 Importante | KPIs: **1 exfiltración crítica · 5/5 detectadas · 0 falsos positivos en cuentas normales · anticipación de 16 días** |
| T7 | **Sección 2 (Adversarios) es un párrafo genérico.** La ficha pide actores, motivaciones, objetivos, capacidades, TTP y **evidencias** | 🟠 Importante | Tabla por campaña con el **Modelo Diamante** (sección 5.2) |
| T8 | **Sección 4 (Táctica):** lista técnicas sueltas sin decir en qué campaña ni qué táctica | 🟠 Importante | Matriz **campaña × táctica** |
| T9 | **Sección 5:** pone Admiralty (A2, B3) por campaña. Admiralty califica **fuentes e información**, no campañas. Además faltan fechas, severidad y cifras | 🟠 Importante | Admiralty **por fuente** en la sección 1; **confianza (alta/media/baja)** por campaña en la sección 5, con fecha y conteos |
| T10 | **"47 anomalías médico/período sin confirmar"** suena a 47 falsos positivos, pero **las primeras 16 son las cuentas especiales**, que las reglas sí confirman | 🟠 Importante | Explicarlo: "las 16 primeras coinciden con las cuentas especiales; el resto queda para revisión" |
| T11 | **Falta la obligación de notificar (LOPDP art. 43, máximo 5 días)**, y cita los arts. 25 y 37 sin verificar (el art. 40 sí trata del análisis de riesgos) | 🟠 Importante | Agregar el art. 43 en la sección 3. Rol 5 verifica los arts. 25 y 37 |
| T12 | **Falta una tabla de IoC** (indicador, tipo, contexto, acción, TLP) y la lista de IoA con su lógica | 🟡 Menor | Tabla en la sección 6 (5.6 de este documento) |
| T13 | **Falta "Brechas de inteligencia y limitaciones"** (volumen exfiltrado desconocido, atribución no confirmada, datos sintéticos) | 🟡 Menor | Agregarla en la sección 8 |
| T14 | **Los hashes SHA-256 en la página 1** ocupan espacio clave | 🟡 Menor | Moverlos a un **Anexo de integridad** al final |
| T15 | Falta el **control del documento** (fecha, versión, destinatarios, periodo, analista) | 🟡 Menor | Una línea bajo el título |

✅ **Lo que está bien y hay que conservar:** la IP "defangeada" (`186.46.219[.]18`), la cronología con el ajuste de +12 h, el mapa de calor, la matriz IPE de probabilidad × impacto, la priorización por plazos y el sello SHA-256.

---

## 4. REPORTE TÉCNICO — nueva página 1: "0 · Resumen de inteligencia" (texto listo)

---
**AegisHealth-CTI · Reporte de inteligencia de amenazas (Ficha F-11)**
Periodo: 01–31 oct 2026 · Emitido: 27-nov-2026 · v1.0 · **TLP:AMBER** · Para: SOC / Seguridad de la Información IESS · Datos sintéticos de ejercicio

**Juicio clave.** Es **probable** que la plataforma médica enfrente **abuso interno persistente de cuentas privilegiadas** (CAMP-2026-005: 11 cuentas especiales compartidas por hasta 1.737 identidades, activas desde el 1-oct). Es **posible** que esa actividad esté vinculada a la **exfiltración del 24-oct** (CAMP-2026-001: SSH al servidor clínico → descarga → salida a `186.46.219[.]18:8443` en **30 segundos**). Confianza en el vínculo: **baja-media** (solo 1 de 811 conexiones al 8443 sale al exterior).

**Campañas, por prioridad**
| Prioridad | Campaña | Qué pasó | Fecha (hora local) | Severidad | Confianza | Acción inmediata |
|---|---|---|---|---|---|---|
| 1 | CAMP-2026-001 | SSH → descarga → salida externa por 8443 | 24-oct 22:40 | **CRÍTICA** | Alta | Bloquear el egreso no autorizado e investigar la descarga |
| 2 | CAMP-2026-005 | Abuso de 11 cuentas especiales compartidas (activaciones, reactivaciones, cambios de nivel) | 1–31 oct | ALTA | Alta | Suspender, rotar credenciales y exigir cuentas nominales + MFA |
| 3 | CAMP-2026-004 | Escaneo de RDP, SMB, BD y NetBIOS + spraying | 19-oct 14:00 | ALTA | Alta | Aislar `10.10.100.20`; cerrar SMBv1 |
| 4 | CAMP-2026-002 | 30 sesiones SSH + 2.970 transferencias interrumpidas | 7-oct 13:00 | ALTA | Alta | Limitar SSH al servidor por bastión; DLP |
| 5 | CAMP-2026-003 | Fuerza bruta Telnet (2.000 intentos) | 10-oct 00:00 | ALTA | Alta | Desactivar Telnet 23 |

**Cifras clave**
| 10.023.532 registros | Calidad 99,99% / 99,97% | Reglas IoA **5/5** | ML sin reglas **4/5** (5/5 con dominio) | **0** de 10.000 cuentas normales marcadas | Anticipación **16 días** | **2** falsas alarmas en 744 h |
|---|---|---|---|---|---|---|

**Cinco acciones prioritarias**
1. **Bloquear el egreso** desde la red clínica salvo lista blanca; IoC `186.46.219[.]18:8443` (regla `ioc_01`).
2. **Suspender las 16 cuentas especiales**, rotar credenciales, cuentas nominales y MFA.
3. **Restringir el acceso al servidor `10.10.100.30`** (SSH/RDP/SMB) a un bastión; desactivar Telnet 23 y SMBv1.
4. **Desplegar las 10 reglas Sigma** y cargar el STIX 2.1 en MISP.
5. **Conservar la evidencia y evaluar la notificación** a la Superintendencia de Protección de Datos Personales (LOPDP art. 43: máximo 5 días).
---

---

## 5. REPORTE TÉCNICO — cambios por sección (se mantiene el orden de la ficha)

**Orden final:** 0 Resumen (nuevo) → 1 Fuentes y metodología → 2 Adversarios → 3 Estratégica → 4 Táctica → 5 Operativa → 6 Técnica → 7 Escenarios IPE + Anticipación → 8 Conclusiones, brechas y controles → Anexo A (integridad: hashes y sello) → Anexo B (calidad y privacidad).

### 5.1 · Sección 1 — Fuentes y metodología (más corta)
| Fuente | Tipo | Admiralty | Motivo |
|---|---|---|---|
| Registros del firewall (5.009.031) | Interna (técnica) | **B2** | Fuente fiable; información probable (2.607 duplicados, 493 IP sin puntos reparadas) |
| Registros del sistema médico (5.014.501) | Interna (técnica) | **B3** | Fuente fiable; credibilidad media por el desfase de 12 h y el formato de las IP |
| Mentorías del IESS | HUMINT | B2 | Especialistas de la institución |
| MITRE ATT&CK | OSINT | A1 | Marco de referencia de la industria |

Metodología: ciclo de inteligencia + IPE + Modelo Diamante + ML local (Isolation Forest) + reglas IoA/IoC. Los hashes SHA-256 se mueven al **Anexo A**.

### 5.2 · Sección 2 — Adversarios (Modelo Diamante)
| Campaña | Adversario | Capacidad | Infraestructura | Víctima | Motivación probable |
|---|---|---|---|---|---|
| 001 | Híbrido: insider o cuenta comprometida | SSH + cuenta válida + egreso cifrado | `10.10.100.40` → `186.46.219[.]18:8443` | Servidor clínico `10.10.100.30` | Venta o extorsión de datos de salud |
| 005 | Insider con privilegios | Administración de cuentas | 11 cuentas especiales compartidas | Control de acceso del sistema médico | Persistencia / preparación de accesos |
| 004 | Actor con presencia interna | Escaneo + spraying | `10.10.100.20` | Servicios RDP, SMB, BD (8471) | Reconocimiento previo a un acceso |
| 002 | Actor con presencia interna | Automatización por SSH | `10.10.100.50` | Repositorio clínico | Extracción masiva |
| 003 | Actor con presencia interna | Fuerza bruta | `10.10.100.10` | Telnet del servidor | Obtener credenciales |

### 5.3 · Sección 3 — Inteligencia estratégica
Agregar: impacto en **confidencialidad, integridad y disponibilidad** con datos (1 posible exfiltración; 131 cambios de nivel, 1.098 activaciones y 826 reactivaciones; sin evidencia de caída) + la obligación del **LOPDP art. 43 (máximo 5 días)** + Política IESS art. 27 y EGSI 1.7.

### 5.4 · Sección 4 — Táctica: matriz campaña × táctica
| Táctica | 001 | 002 | 003 | 004 | 005 |
|---|---|---|---|---|---|
| Reconocimiento | | | | T1046 | |
| Acceso a credenciales | | | T1110.001 | T1110.001, T1110.003 | |
| Cuentas válidas | T1078 | | | T1078 | T1078 |
| Persistencia / privilegios | | | | | T1098 |
| Movimiento lateral | T1021.004 | T1021.004 | T1021 | T1021.001, T1021.002 | |
| Recolección | T1213 | T1213, T1074 | | | |
| Exfiltración | T1048.002 | | | | |
| Impacto | | | | | T1531 |

### 5.5 · Sección 5 — Operativa
Por campaña: fecha y hora local, conteos (por ejemplo, 003: 2.000 intentos negados ↔ 2.000 accesos fallidos), reglas que la detectaron (IOA-xx), **confianza** y la cronología de 001 **con la hora original y la ajustada**:
| Hora original | Hora ajustada | Fuente | Evento |
|---|---|---|---|
| 22:40:00 | — | Firewall | SSH `10.10.100.40` → `10.10.100.30` (permitido) |
| 10:40:00 | 22:40:00 (+12 h) | Sistema médico | INGRESO SIST_MED_IESS |
| 10:40:15 | 22:40:15 (+12 h) | Sistema médico | DESCARGA EXITOSA |
| 22:40:30 | — | Firewall | Salida a `186.46.219[.]18:8443` (permitido) |

Pie del mapa de calor: "Hora local del registro. Los picos corresponden a los incidentes C (7-oct 13 h), A (10-oct 00 h) y B (19-oct 14 h)."

### 5.6 · Sección 6 — Técnica: tablas de IoC y de IoA
| Indicador | Tipo | Contexto | Acción | TLP |
|---|---|---|---|---|
| `186.46.219[.]18:8443` | IP:puerto destino | Exfiltración 001 (sintético) | Bloquear | AMBER |
| `10.10.100.10`, `.20`, `.40`, `.50` | IP origen interna | Equipos de las campañas | Aislar o revisar | AMBER |
| `10.10.100.30` | Activo crítico | Servidor del sistema médico | Proteger o monitorear | AMBER |
| 16 cuentas `ACC-…` | Cuenta técnica seudonimizada | Abuso o compromiso | Suspender o rotar | AMBER |

IoA: listar IOA-01 a IOA-09 con su umbral (de `hallazgos_reglas.json → umbrales`). ML: "4/5 genérico, 5/5 dominio; las 16 cuentas especiales en los puestos 1 a 16 de 10.016". Productos: 10 reglas Sigma y STIX 2.1 (82 objetos, compatible con MISP).

### 5.7 · Sección 7 — Escenarios IPE + Anticipación (nuevo bloque)
Conservar la matriz de probabilidad × impacto y agregar:
| Nivel de anticipación | Resultado validado (sin mirar el futuro) |
|---|---|
| Riesgo previo por cuenta | Cuenta del incidente B en riesgo **CRÍTICO 16 días antes**; las de E, desde el día 1 |
| Alerta temprana | A, B, C y D alertados **en la misma hora**; **2 falsas alarmas en 744 h** |
| Siguiente fase | Acierta **4/5** en su top 3, con un control recomendado por fase |
| Velocidad del ataque | 001: **30 s** del SSH a la exfiltración → la contención debe ser **automática** |

### 5.8 · Sección 8 — Conclusiones + brechas de inteligencia
Conservar la tabla de controles por plazo y agregar:
**Brechas y limitaciones:** (1) no se conoce el volumen ni el contenido de la descarga del 24-oct; (2) el vínculo 005 → 001 es posible, no probable; (3) no hay atribución a un actor concreto; (4) los datos son sintéticos y las cifras se deben recalibrar con datos reales; (5) las cuentas de A, C y D no tenían historial, así que no se pudieron anticipar (sí se detectaron en la misma hora).

---

## 6. De dónde sale cada cifra (para el generador del Rol 3)

| Cifra | Archivo (`data/exports_10m/`) | Campo |
|---|---|---|
| 10.023.532 registros, calidad 99,99 / 99,97 | `calidad_datos.json` | `firewall.filas` + `sistema_medico.filas`, `puntaje_calidad` |
| IoA 5/5 | `hallazgos_reglas.json` | `incidentes_detectados_por_ioa` |
| ML 4/5 y 5/5 | `ml_metrics_A_genericas.json` / `_B_dominio.json` | `incidentes_en_top_n` |
| Campañas, técnicas, severidad, fechas | `campanas.json` | `campaigns[]` |
| Escenarios IPE | `campanas.json` | `escenarios_ipe` |
| 16 días, alertas, siguiente fase | `anticipacion.json` | `backtest_incidentes`, `alertas_tempranas`, `backtest_siguiente_fase` |
| 11 cuentas compartidas, hasta 1.737 identidades | `hallazgos_reglas.json` | reglas `IOA-06` → `identidades_distintas` |
| 0 cuentas normales marcadas | Verificado por el Rol 2 | Todas las cuentas de IOA-06/07/08 son especiales |

**Prompt para Ollama (ambos reportes):** "Redacta usando EXCLUSIVAMENTE las cifras del JSON. Empieza por la conclusión y las acciones. Distingue hecho de hipótesis ('probable', 'posible'). Si un dato no está en el JSON, escribe 'por confirmar'. No inventes." En el ejecutivo, además: "Sin siglas técnicas. Cada acción con responsable y plazo".

---

## 7. Lista de verificación antes de subir a Drive

- [ ] El ejecutivo empieza con "Lo más importante" y "Lo que necesitamos que usted autorice hoy".
- [ ] El técnico empieza con "0 · Resumen de inteligencia" (juicio clave + campañas por prioridad + 5 acciones).
- [ ] TLP:AMBER en los dos (no RED).
- [ ] Sin "Pendiente de revisión", sin "Rol 1" ni "Rol 5" en el texto.
- [ ] Horas como "hora local del registro" (sin "+00:00" ni "UTC").
- [ ] Anticipación incluida (16 días · misma hora · 2 falsas alarmas · 4/5).
- [ ] LOPDP art. 43 (notificación en máximo 5 días) incluido; arts. 25 y 37 verificados en el texto oficial.
- [ ] IP externa siempre defangeada: `186.46.219[.]18`.
- [ ] Sin nombres ni códigos de cuenta en claro.
- [ ] Hashes y sello SHA-256 en el anexo final.
