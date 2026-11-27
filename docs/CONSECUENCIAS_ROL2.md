# Consecuencias del ataque + correcciones de los reportes (Rol 2)

**Rama:** `feat/consecuencias-reportes` (sale de `main` becf8d8) · **Pruebas:** `tests/test_consecuencias.py` (8) + las existentes de reportes, Guardián y Centinela siguen pasando.

## 1. Qué se agregó: "qué puede hacer el atacante" (casos reales)

Cuando se vulnera algo, el sistema explica de forma directa qué puede hacer el atacante con eso. **Regla del catálogo:** cada consecuencia tiene un caso real y público con fuente; no se incluyen suposiciones sin precedente. El catálogo no tiene nombres de víctimas ni de investigados.

| Qué se vulneró | Qué puede hacer el atacante | Caso real |
|---|---|---|
| Datos de salud (CAMP-2026-001, 002) | Extorsionar a cada paciente · publicar diagnósticos sensibles · usar su identidad médica | Vastaamo 2020 · Medibank 2022 · FTC |
| Cuentas administrativas compartidas (CAMP-2026-005, GUARD-04) | Cambiar los datos de afiliados y sacar préstamos a su nombre sin que se sepa quién fue | Préstamos fraudulentos a jubilados, Ecuador 2024 |
| Claves de cuentas técnicas (CAMP-2026-003, 004) | Entrar con la clave robada, copiar datos y cifrar los sistemas | Change Healthcare 2024 |
| Servicios antiguos expuestos (CAMP-2026-004) | Propagar un programa malicioso por SMB y paralizar la atención | WannaCry en el NHS 2017 |
| Identidad del afiliado (GUARD-01/02/03, Centinela) | Tomar la cuenta y sacar préstamos · retirar fondos | Ecuador 2024 · intento de retiro de cesantía |

**Dónde aparece:**
- **Reporte técnico:** nueva sección **3.1** (tabla + fuentes con URL).
- **Reporte ejecutivo:** página 2, "Qué puede hacer un atacante con lo que se expuso", en lenguaje simple y sin siglas. Por decisión del equipo, el ejecutivo **no** muestra los casos ni las fuentes; esos quedan en el técnico y en la API.
- **API:** `GET /api/v1/consequences` (catálogo) y `GET /api/v1/consequences/{code}` (con `CAMP-2026-001`, `IOA-05`, `GUARD-01` o `CEN-001`). La respuesta viene en camelCase. Para el panel (Rol 4): al abrir una campaña o un caso del Guardián, llamar `/api/v1/consequences/{code}` y mostrar `actionSimple` + `caseName` + `caseFactSimple`.

Archivo de contenido: `app/cti_exports/consecuencias.py`. Para agregar un caso, se agrega en `CASOS` (con `url`) y se referencia desde `CONSECUENCIAS`.

## 2. Correcciones del reporte técnico (todas estaban en el PDF v7)

| Antes | Ahora |
|---|---|
| Tarjeta "5/5 · 5/5 (ML / IoA)" (el ML sin reglas es 4/5) | "IoA 5/5 · ML 4/5" |
| Sección 8: "Acción prioritaria: priorizar la sincronización de los relojes" | La acción prioritaria es **fija** (bloquear el egreso, suspender las cuentas, LOPDP art. 43). Ollama solo elige un "control complementario" |
| Letras A–E en la sección 7, en las brechas y en el pie del mapa de calor | Nombres CAMP-2026-00X |
| 10 páginas, 4 casi vacías (saltos de página forzados) | El contenido fluye (unas 8 páginas) |
| Dos filas de KPI repetidas | Una fila de 4 tarjetas + 4 cifras complementarias sin repetir |
| "Ejemplo Sigma" mostraba solo el título | Muestra el YAML real de una regla (IP desactivada) |
| Párrafo legal repetido en el Anexo B; art. 37 sin verificar | Anexo B: "Ver sección 3"; art. 37 retirado (los arts. 25, 30, 40 y 43 sí están verificados) |
| "Conexion", "Trafico", "publica sintetica" y nota del reloj repetida en la cronología | Con tildes y sin la nota repetida |
| "(hora local)" en cada celda; "personas" | Solo en el encabezado; "usuarios" |
| 8470–8478 | 8470–8476 (servidores IBM i; con TLS, 9470–9476) |
| "Edición técnica generada" y "23 registros auditados" | Sello retirado (TLP y "datos sintéticos" ya están en el encabezado y el pie); "eventos de la cadena de auditoría" |
| Sección 7: gráfico 2×2 con dos etiquetas (no aportaba nada) | Gráfico retirado; la tabla muestra las campañas de cada escenario, probabilidad e impacto en color y la **señal de que el escenario está empezando** (IOA-03/04/05/06) |
| Sección 5: "Conteos" y "Hallazgo" decían lo mismo | Columnas: qué se observó · reglas que lo detectaron · confianza |
| Párrafo "Alcance de valoración" y frase repetida bajo el título de la sección 2 | Retirados |
| Nota larga sobre la cronología | "El reloj del sistema médico va 12 h atrasado; se muestra su hora original y la ajustada." |

**IOA-08 (`^10\d{9}$`) no se cambió:** coincide con el ETL del Rol 1 (las IP sin puntos de los datos tienen 11 dígitos).

**Ejecutivo:** el título pasa a una sola línea, dice "usuarios" en lugar de "personas" y tiene una página 2 con contenido real (qué puede hacer el atacante, lo que lo evita y las cifras).

## 3. Después de hacer el merge (obligatorio)

Los textos del reporte cambiaron, así que la huella de los insumos cambia y la caché de Ollama anterior ya no sirve:
```powershell
.\.venv\Scripts\python.exe -m app.cti_exports.cache_f11
.\.venv\Scripts\python.exe -m app.cti_exports.cache_f11 --aprobar
.\.venv\Scripts\python.exe -m pytest -q
```
Después, generar de nuevo los dos PDF desde la API y revisarlos. El Rol 2 validó la maquetación con Chrome; la versión final la genera WeasyPrint, así que hay que revisar el salto de página entre las páginas 1 y 2 del ejecutivo.
