# ENTREGA DEL ROL 2 — ML local, reglas IoA/IoC, MITRE ATT&CK, Sigma y STIX 2.1
**Proyecto:** AegisHealth-CTI · Hackatón IESS 2026 · Reto 3 (Ficha F-11)
**De:** Rol 2 (rama `feat/ml-cti`) · **Fecha:** jueves 26-nov-2026, 15:30
**Estado:** ✅ Código terminado y probado con la muestra oficial de Rol 1 (210.480 + 220.029 filas).
⏳ Falta la corrida con los 10M de filas (sección 2, Rol 1).

---

## 0. Resumen para todos (lean esto primero)

| Qué | Resultado (muestra) |
|---|---|
| Reglas de comportamiento (IoA) | **5/5 incidentes detectados** |
| ML sin reglas, solo variables genéricas (Isolation Forest) | **4/5** (A, B, C y E; el D es un evento único y lo cubren las reglas) |
| ML con variables de dominio | **5/5** |
| Perfil por cuenta (ML) | Los **16 primeros puestos son exactamente las 16 cuentas especiales**, sin que el modelo sepa cuáles son |
| Campañas armadas automáticamente | **5**, iguales a las del contrato (CAMP-2026-001 a 005) |
| Reglas Sigma | **10** (8 IoA + 2 IoC), YAML validado |
| STIX 2.1 para MISP | **82 objetos**, **validado con la librería oficial `stix2`** |
| Datos personales en las salidas | **Ninguno** (solo tokens `USR-`/`ACC-`; búsqueda verificada) |

Un solo comando corre todo (desde la raíz del repo):
```powershell
python -m backend.app.analytics.pipeline_rol2 --fw <parquet_firewall> --med <parquet_sistema_medico> --salida data\exports
```

---

## 1. Archivos que entrego

**Código (por GitHub, rama `feat/ml-cti`):**
```
backend/app/analytics/
  carga.py                     # Lee Parquet/CSV, solo columnas necesarias (minimización LOPDP)
  ml_detector.py               # Isolation Forest: 3 tablas de ventanas, versiones A y B, métricas
  rules_engine.py              # 9 reglas IoA + 4 IoC, cada hallazgo con sus filas de evidencia
  mitre_mapper.py              # Campañas, técnicas MITRE ATT&CK y 2 escenarios IPE
  pipeline_rol2.py             # Corre los 5 pasos en orden
  incidentes_referencia.json   # Verdad conocida SOLO para evaluar (nunca para entrenar)
  iocs_ejercicio.json          # IoC sintéticos con etiqueta de ejercicio
backend/app/cti_exports/
  sigma_generator.py           # 10 reglas Sigma (formato de correlación para umbrales)
  stix_exporter.py             # Bundle STIX 2.1 con TLP:AMBER y candado ético
requirements-rol2.txt          # pandas, pyarrow, numpy, scikit-learn, pyyaml, stix2
```

**Salidas (por USB, nunca a GitHub): carpeta `data/exports/`**
```
ml_metrics_A_genericas.json    ml_metrics_B_dominio.json
ranking_*.csv (6)              hallazgos_reglas.json
campanas.json                  aegishealth_stix21_bundle.json
sigma/*.yml (10)
```

---

## 2. PARA ROL 1 (Datos) — 2 pedidos

### 2.1 Correr el pipeline con los 10M de filas (lo antes posible)
En mi laptop no alcanza la RAM (12 GB en total). En una prueba de carga con unos 10 millones de filas tardó **unos 3 minutos y usó unos 3,2 GB de RAM**.
1. Descomprime el zip del Rol 2 en la raíz de tu repo (o haz `git pull` de `feat/ml-cti`).
2. Instala lo que falte: `python -m pip install -r requirements-rol2.txt` (Polars no hace falta para esta parte).
3. Corre:
   ```powershell
   python -m backend.app.analytics.pipeline_rol2 --fw data\processed\fw_seudonimizado.parquet --med data\processed\med_seudonimizado.parquet --salida data\exports_10m
   ```
4. Pasa la carpeta `data\exports_10m` por USB a **Rol 3** y a **Rol 5**, y avísame las cifras que salgan en pantalla.

### 2.2 Agregar la columna `event_id` a los Parquet
Hoy la evidencia se cita como `fila_origen`, la posición de la fila dentro del Parquet. Si agregas `event_id`, el número de fila original del CSV, el código lo detecta solo y cita ese número. Así la evidencia queda trazable hasta el CSV oficial.

---

## 3. PARA ROL 3 (Backend, integración y PDF)

### 3.1 Integración
- Revisa y haz merge del PR `feat/ml-cti` → `main`.
- Agrega el contenido de `requirements-rol2.txt` a `backend/requirements.txt`.
- En la Laptop #6, corre el pipeline (o usa `data/exports_10m` de Rol 1) y deja los JSON donde los lea la API.

### 3.2 Funciones que puedes llamar desde FastAPI
```python
from backend.app.analytics import ml_detector, rules_engine, mitre_mapper
from backend.app.cti_exports import sigma_generator, stix_exporter

ml_detector.ejecutar(ruta_fw, ruta_med, carpeta)          # -> dict con métricas A y B
rules_engine.ejecutar(ruta_fw, ruta_med, carpeta)         # -> dict con hallazgos IoA/IoC y cobertura
mitre_mapper.ejecutar(carpeta)                            # -> {"campaigns": [...], "escenarios_ipe": {...}}
sigma_generator.generar_reglas_sigma(carpeta + "/sigma")  # -> lista de rutas .yml
stix_exporter.exportar_bundle_stix(carpeta)               # -> ruta del bundle
```

### 3.3 De dónde sale cada endpoint del contrato
| Endpoint | Archivo fuente |
|---|---|
| `GET /api/v1/campaigns` | `campanas.json` → `campaigns` |
| `GET /api/v1/campaigns/{code}/timeline` | `campanas.json` → `first_seen`, `last_seen`, `hallazgos`, `evidence_refs` |
| `GET /api/v1/exports/sigma` | `sigma/*.yml` |
| `GET /api/v1/exports/stix` | `aegishealth_stix21_bundle.json` |
| `GET /api/v1/dashboard/summary` | `ml_metrics_*.json` + `hallazgos_reglas.json` → `resumen_por_regla` |

### 3.4 Diferencias con el contrato original (importante)
- Las claves están en **snake_case** (`campaign_code`, `mitre_techniques`…). El paso a camelCase hazlo en la API.
- **IPE ya no es una etiqueta por campaña.** Son **2 escenarios globales** en `campanas.json → escenarios_ipe` (`ESCENARIO_MAS_PROBABLE` y `ESCENARIO_MAS_PELIGROSO`), como pide la metodología.
- `adversary_type` usa: `HYBRID`, `INSIDER_THREAT`, `ACTOR_CON_PRESENCIA_INTERNA`. No usamos `EXTERNAL_ACTOR`: los orígenes son IPs internas y no hay evidencia de un actor externo.
- `anomaly_score` sale del ML (versión genérica). Si una entidad no está en el top 200 del ranking, vale 0.

### 3.5 Para el LLM local (Ollama)
Pásale **solo `campanas.json`** (ya está agregado y seudonimizado), nunca filas crudas ni `hallazgos_reglas.json` completo.

---

## 4. PARA ROL 4 (Frontend War Room)

### 4.1 Estructura de una campaña (`campanas.json → campaigns[i]`)
```json
{
  "campaign_code": "CAMP-2026-001",
  "adversary_type": "HYBRID",
  "severity": "CRITICA",
  "anomaly_score": 0.0,
  "first_seen": "2026-10-24 22:40:00",
  "last_seen": "2026-10-24 22:40:30",
  "summary": "Salida de datos hacia IP externa",
  "mitre_techniques": [{"id": "T1048.002", "name": "...", "tactic": "Exfiltration", "url": "https://attack.mitre.org/..."}],
  "iocs": {"source_ips": [], "destination_ips": [], "actor_tokens": [], "account_tokens": []},
  "ioas": ["IOA-05"],
  "hallazgos": ["Texto en español de cada hallazgo..."],
  "evidence_refs": [{"dataset": "firewall", "referencia": "fila_origen", "total_filas": 2, "primeras_filas": [167689, 167739]}]
}
```
`severity` puede ser `CRITICA`, `ALTA` o `MEDIA` (en español).

### 4.2 Ideas de pantallas con estos datos
1. **"ML vs reglas":** dos tarjetas: "Reglas IoA: 5/5" y "ML sin reglas: 4/5 (genérico) · 5/5 (dominio)". Sale de `ml_metrics_*.json → incidentes_en_top_n` y `hallazgos_reglas.json → incidentes_detectados_por_ioa`.
2. **Matriz MITRE:** técnicas agrupadas por `tactic`, coloreadas según cuántas campañas las usan.
3. **Ranking de anomalías:** tabla con el top 20 de `ranking_med_periodo_A_genericas.csv`, para mostrar que las 16 cuentas especiales salen arriba solas.
4. **IoA vs IoC:** dos columnas: comportamiento general frente a indicadores concretos.
5. **Escenarios IPE:** dos tarjetas, "Más probable" y "Más peligroso", desde `escenarios_ipe`.

Todos los indicadores son tokens seudonimizados: muéstralos tal cual, nunca intentes "traducirlos".

---

## 5. PARA ROL 5 (Analista CTI, reporte F-11 y QA)

### 5.1 Qué aporta el Rol 2 a cada sección del reporte
| Sección F-11 | Fuente |
|---|---|
| 1. Fuentes y metodología | Datasets internos + Isolation Forest + reglas IoA/IoC + MITRE ATT&CK + IPE. Puedes citar: "los incidentes conocidos solo se usaron para evaluar, nunca para entrenar" |
| 2. Adversarios | `campanas.json` → `adversary_type`, `ioas` y `hallazgos` |
| 4. Táctica (TTP) | `campanas.json` → `mitre_techniques` |
| 5. Operativa (campañas) | `campanas.json` → las 5 campañas con fechas |
| 6. Técnica (IoC, IoA, reglas) | `hallazgos_reglas.json` + `sigma/*.yml` + `aegishealth_stix21_bundle.json` |
| 7. Escenarios IPE | `campanas.json → escenarios_ipe` |

### 5.2 Cifras que puedes usar (ACTUALIZAR con la corrida de 10M de Rol 1)
- Reglas IoA: 5/5 incidentes. 48 hallazgos IoA y 13 IoC. Ninguna cuenta normal marcada.
- ML sin reglas (versión A, genérica): 4/5. A, B y C en los puestos 1, 2 y 3 de 166.953 ventanas del firewall; E en los puestos 5, 7 y 11 de 10.016 cuentas.
- ML versión B (dominio): 5/5.
- Las 16 cuentas especiales ocupan los puestos 1 a 16 del perfil por cuenta.
- Cuentas normales: 1 identidad por cuenta. Cuentas especiales: entre 108 y 1.737 identidades.

### 5.3 Frases que debemos decir con honestidad
- "Las cifras de la muestra son optimistas: la muestra concentra los incidentes. Las oficiales son las de los 10M."
- "Tres ajustes del modelo (conteos, logaritmo y 20.000 muestras por árbol) se eligieron mirando la muestra y quedaron fijos antes de la corrida de 10M."
- "El ML detecta ráfagas y abuso lento; las reglas detectan eventos únicos como la salida a la IP externa. Se complementan."
- "El vínculo entre CAMP-005 y CAMP-001 es **posible**, no probable: solo 1 de las 811 conexiones al puerto 8443 sale a la IP externa."
- "Las reglas IOA-08 (IP sin puntos) no tienen técnica ATT&CK asignada: es una hipótesis de evasión o de manipulación de registros que requiere análisis."
- "La IP 186.46.219.18 es un dato sintético: no se consultó ni se escaneó, y está etiquetada como ejercicio en STIX y Sigma."

### 5.4 Uso de IA (lo pide la guía del hackatón)
- **IA de internet:** se usó como asistente para desarrollar el código del Rol 2, solo con los datos sintéticos de la muestra (lo permite el numeral 6 de la ficha).
- **IA o ML del producto:** Isolation Forest de scikit-learn, que corre 100% local, en CPU.
- **Criterio humano:** revisión de umbrales, técnicas MITRE, clasificación de adversarios y redacción de conclusiones.

### 5.5 Checklist de QA para mis salidas
- [ ] No aparece `XYZ`, `WXY`, `MINAD`, `CMAP` ni `RIMODE` en ningún archivo de `data/exports` (cuentas en claro).
- [ ] Todo indicador STIX lleva `synthetic-exercise-data` y `hackathon-simulation`.
- [ ] Las cifras del PDF coinciden con `ml_metrics_*.json` y `hallazgos_reglas.json` de la corrida de **10M**.

---

## 6. Cómo se entrega

| Qué | Cómo | A quién |
|---|---|---|
| Código | GitHub, rama `feat/ml-cti` y Pull Request hacia `main` | Rol 3 revisa y hace merge |
| `data/exports/` (muestra) | USB | Rol 3 (Laptop #6) y Rol 5 |
| `data/exports_10m/` | USB (lo genera Rol 1) | Rol 3 y Rol 5 |
| Este documento | Chat del equipo y `docs/` | Todos |

Dudas sobre el Rol 2: escríbanme.
