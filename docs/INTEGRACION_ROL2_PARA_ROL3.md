# Integración del Rol 2 en el backend — Guía para ROL 3
**Proyecto:** AegisHealth-CTI · Hackatón IESS 2026 · Reto 3 (Ficha F-11)
**De:** Rol 2 (ML local y motor CTI) · **Para:** Rol 3 (backend FastAPI, integración de `main`, Ollama, PDF y Laptop #6)
**Fecha:** jueves 26-nov-2026, 17:30

> **Resumen en 3 líneas.** El Rol 2 está terminado y probado con los **10.023.532 filas** reales: **16/16 pruebas automáticas superadas**.
> La API **no** tiene que ejecutar el análisis: solo **lee los resultados** de la carpeta `exports_10m`. Te dejo listos 2 archivos
> (`app/servicios/inteligencia.py` y `app/api/rutas_cti.py`) con el mismo estilo de tu código. **No agregan dependencias nuevas a la imagen Docker.**

---

## 1. Qué hizo el Rol 2 (para que lo puedas explicar en la demo)

Pipeline de 7 pasos que corre **100% local, en CPU**: unos 4 minutos y 2,5 GB de RAM para los 10M de filas.

| Paso | Qué hace | Resultado con 10M de filas |
|---|---|---|
| 0. Calidad y contrato de datos | Revisa columnas, vacíos, duplicados, IPs inválidas y **valores nuevos** (cambios en los datos) | Firewall 99,99% · Sistema médico 99,97% · sin valores nuevos |
| 1. ML sin reglas (Isolation Forest) | 3 tablas de ventanas (firewall por usuario y hora, sistema médico por cuenta y hora, perfil de cada cuenta en el periodo) | **4/5** con variables genéricas (A puesto 1 y B puesto 2 de 694.383 ventanas) · **5/5** con variables de dominio · **las 16 cuentas especiales en los puestos 1 a 16 de 10.016** sin decirle cuáles son |
| 2. Reglas IoA / IoC | 9 reglas de comportamiento + 4 de indicadores; cada hallazgo guarda las filas que lo prueban | **5/5 incidentes**; **0 de 10.000 cuentas normales** marcadas |
| 3. Campañas + MITRE ATT&CK + IPE | Agrupa hallazgos que comparten equipo, usuario o cuenta; asigna técnicas solo con evidencia; arma 2 escenarios IPE | **5 campañas automáticas** (CAMP-2026-001 a 005) |
| 4. Sigma | Reglas de detección portables a cualquier SIEM | 10 reglas (8 IoA + 2 IoC), YAML válido |
| 5. STIX 2.1 | Paquete de inteligencia importable en MISP, TLP:AMBER | 82 objetos, **validado con la librería oficial `stix2`**, todos los indicadores con etiqueta de dato sintético |
| 6. Anticipación | Riesgo previo por cuenta + alerta temprana por línea base + pronóstico de la siguiente fase | Cuenta del incidente B en riesgo CRÍTICO **16 días antes**; A–D alertados **en la misma hora**; **2 falsas alarmas en 744 horas**; siguiente fase 4/5 |

### Mejoras frente al contrato original
1. **Anticipación** (nuevo requerimiento del equipo), validada sin mirar el futuro. No promete "adivinar la fecha" de un ataque, porque con 5 incidentes eso sería sobreajuste.
2. **Control de calidad a la entrada**: si los datos reales del IESS cambian (columnas o valores nuevos), el sistema avisa antes de analizar.
3. **ML honesto**: dos versiones (genérica y de dominio), evaluación por ranking y los incidentes conocidos usados **solo para evaluar**, nunca para entrenar.
4. **MITRE ATT&CK corregido** (T1213, T1074, T1110.001/003, T1048.002; sin T1041 ni T1005 mal aplicados).
5. **IPE correcto**: 2 cursos de acción globales (más probable y más peligroso), no una etiqueta por incidente.
6. **Sin valores fijos**: el riesgo se mide contra lo normal de cada día, y los umbrales se ajustan con `config_rol2.json` sin tocar el código.
7. **Privacidad**: solo tokens `USR-`/`ACC-`; verificado automáticamente que no hay cuentas en claro en ninguna salida.
8. **Hallazgo para la demo**: en el incidente D pasaron **30 segundos** entre el acceso SSH y la salida de datos, así que la contención debe ser automática.

---

## 2. Arquitectura de la integración (decisión clave)

```
 [Laptop #6]                                    [Contenedor backend (tu imagen actual)]
 Parquet 10M ──> pipeline Rol 2 (batch) ──>     data/exports_10m  ──(montado SOLO LECTURA)──>  FastAPI
                 pandas + scikit-learn           JSON / CSV / YAML                               app/servicios/inteligencia.py
                 ~4 min, una vez                 (ya seudonimizados)                             app/api/rutas_cti.py  -> Frontend (Rol 4)
                                                                                                   │
                                                                                                   └─> Ollama: SOLO contexto_para_llm() (~4 KB)
```

**Por qué así:**
- La imagen Docker **no necesita** pandas, scikit-learn ni los 166 MB de Parquet: es más liviana, arranca rápido y tiene menos superficie de ataque.
- Los datos crudos **nunca entran** al contenedor de la API: solo los resultados agregados y seudonimizados (LOPDP: minimización).
- La carpeta se monta como **solo lectura** (`:ro`): la API no puede modificar la evidencia.

---

## 3. Pasos de integración (unos 15 minutos)

### 3.1 Copiar los 2 archivos nuevos (código completo en el Anexo)
```
app/servicios/inteligencia.py    # lee y combina los resultados (solo biblioteca estándar)
app/api/rutas_cti.py             # 10 endpoints, respuestas en camelCase
tests/test_inteligencia.py       # pruebas del servicio
```

### 3.2 Registrar las rutas en `app/main.py`
```python
from fastapi import FastAPI

from app.api.rutas import rutas
from app.api.rutas_cti import rutas_cti

app = FastAPI(title="AegisHealth-CTI API", version="0.2.0")
app.include_router(rutas)
app.include_router(rutas_cti)
```

### 3.3 Montar los resultados en `infra/docker-compose.yml` (servicio `backend`)
```yaml
  backend:
    # ... lo que ya tienes ...
    environment:
      DATABASE_URL: "postgresql://${POSTGRES_APP_USER}:${POSTGRES_APP_PASSWORD}@postgres:5432/${POSTGRES_DB}"
      OLLAMA_BASE_URL: "http://host.docker.internal:11434"
      CTI_EXPORTS_DIR: "/datos/exports"
    volumes:
      - ../data/exports_10m:/datos/exports:ro
```
Sin Docker (uvicorn directo): define `$env:CTI_EXPORTS_DIR="data\exports_10m"` antes de arrancar.

### 3.4 Poner los resultados en la Laptop #6
Descomprime `exports_10m_rol2.zip` (te llega por USB) en `data/exports_10m/` en la raíz del repo.
Ya está en `.gitignore` (regla `data/`): **no se sube a GitHub**.

### 3.5 Probar
```powershell
$env:CTI_EXPORTS_DIR="data\exports_10m"; python tests\test_inteligencia.py      # sin FastAPI: debe decir "OK"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000                     # luego abre http://127.0.0.1:8000/docs
```

---

## 4. Endpoints (todas las respuestas en camelCase)

| Método y ruta | Qué devuelve | Pantalla de Rol 4 |
|---|---|---|
| `GET /api/v1/dashboard/summary` | Filas analizadas, calidad, detección (IoA 5/5, ML 4/5 y 5/5), campañas por severidad, KPIs de anticipación | Inicio / KPIs |
| `GET /api/v1/campaigns` | 5 campañas: severidad, tipo de adversario, técnicas MITRE, IoC, reglas y **siguiente fase probable** | Lista de campañas, matriz MITRE |
| `GET /api/v1/campaigns/{codigo}` | Detalle con hallazgos en español, referencias de evidencia y pronóstico | Detalle |
| `GET /api/v1/campaigns/{codigo}/timeline` | Hallazgos ordenados en el tiempo; `ajusteReloj12h` indica si se corrigió el desfase | Línea de tiempo |
| `GET /api/v1/ipe/escenarios` | Escenario más probable y más peligroso | Escenarios IPE |
| `GET /api/v1/anticipacion` | Cuentas en riesgo con razones, alertas CONFIRMADAS, backtest y siguiente fase | Anticipación |
| `GET /api/v1/exports/sigma` | Lista de las 10 reglas | Visor Sigma |
| `GET /api/v1/exports/sigma/{nombre}` | Descarga de una regla (lista blanca) | Visor Sigma |
| `GET /api/v1/exports/stix` | Bundle STIX 2.1 | Botón "Descargar para MISP" |

Si falta la carpeta de resultados, la API responde **503** con un mensaje claro (no se cae).

---

## 5. Ollama y el PDF F-11

- **Al LLM solo se le pasa** `cti.contexto_para_llm()`: un JSON de unos **4 KB** con KPIs, campañas, técnicas y escenarios IPE, ya seudonimizado. **Nunca** filas crudas ni `hallazgos_reglas.json` completo.
- Prompt sugerido: *"Redacta en español la sección X del reporte F-11 usando EXCLUSIVAMENTE las cifras de este JSON. Si un dato no está, escribe 'no disponible'. No inventes."*
- **Pre-genera** los textos (en CPU tarda minutos) y guárdalos; en la demo genera en vivo solo una sección.
- Para el PDF, las cifras oficiales están en `RESUMEN_RESULTADOS_10M.md` y la anticipación en `ANTICIPACION_ROL2.md` (los dos dentro de `exports_10m`).

---

## 6. Seguridad incluida (para la mentoría de seguridad del viernes 11:00)

| Control | Dónde |
|---|---|
| Datos crudos fuera de la API; solo resultados agregados y seudonimizados | Arquitectura (sección 2) |
| Carpeta montada en solo lectura | `docker-compose.yml` (`:ro`) |
| Descarga de Sigma con lista blanca + regex (bloquea path traversal como `../../.env`) | `ruta_sigma()` |
| Error 503 controlado sin exponer rutas internas del sistema | `_seguro()` en las rutas |
| Contexto mínimo para el LLM (unos 4 KB, sin filas) | `contexto_para_llm()` |
| Sin dependencias nuevas en la imagen | El servicio usa solo la biblioteca estándar |
| API solo en `127.0.0.1:8000` | Ya lo tienes en el compose ✅ |

---

## 7. El rol de cada uno con estos resultados

| Rol | Qué hace ahora |
|---|---|
| **Rol 1** | Agregar `event_id` a los Parquet (opcional): así la evidencia queda trazable hasta el CSV. Si lo agrega, se vuelve a correr el pipeline (unos 4 min). |
| **Rol 2** | Terminado. Soporte a la integración y defensa técnica de ML, reglas y anticipación en la demo. |
| **Rol 3 (tú)** | Integrar los 2 archivos, montar `exports_10m`, conectar Ollama con `contexto_para_llm()` y generar el PDF. Decidir `app/` frente a `backend/app/` (ver sección 8). |
| **Rol 4** | Consumir los endpoints de la sección 4. Pantalla nueva de **Anticipación** (descrita en `ANTICIPACION_ROL2.md`). |
| **Rol 5** | Cifras oficiales desde `RESUMEN_RESULTADOS_10M.md`; sección 7 del reporte (escenarios y anticipación) desde `ANTICIPACION_ROL2.md`; QA final. |

---

## 8. Pendientes y decisiones

1. **Estructura de carpetas:** `main` usa `app/`, y Rol 1 y Rol 2 usan `backend/app/`. **Recomendación:** dejar el análisis en `backend/app/` (es *batch*, corre fuera de la API) y la API en `app/`. Así tu Dockerfile no cambia.
2. **Mi rama `feat/ml-cti`** no se pudo subir (error 403: no tengo permiso de escritura). Agrégame como colaborador o te llega un Pull Request desde mi fork.
3. **PostgreSQL:** tu compose usa `postgres:16-alpine`. Funciona. La 18 es la estable actual; si cambias, el volumen se monta en `/var/lib/postgresql`.
4. **Regenerar resultados** (solo si cambian los datos), desde la raíz del repo con el entorno del Rol 2:
   `python -m backend.app.analytics.pipeline_rol2 --fw data/processed/fw_seudonimizado.parquet --med data/processed/med_seudonimizado.parquet --salida data/exports_10m`
   y después `python tests/verificar_rol2.py --salida data/exports_10m` (debe dar 16/16).

---

## Anexo A — `app/servicios/inteligencia.py`
```python
"""
Servicio de inteligencia de amenazas: LEE los resultados que genera el Rol 2 (carpeta exports).

Decisión de diseño: la API NO ejecuta el análisis (pandas, scikit-learn, 10M de filas).
El análisis corre aparte (pipeline del Rol 2) y la API solo sirve los resultados ya
seudonimizados. Así la imagen Docker queda liviana, no contiene datos crudos y hay
menos superficie de ataque.

Solo usa la biblioteca estándar de Python.
"""
import csv
import json
import os
import re
from functools import lru_cache
from pathlib import Path

NOMBRE_SIGMA_VALIDO = re.compile(r"^(ioa|ioc)_\d{2}_[a-z0-9_]+\.yml$")


class DatosNoDisponibles(Exception):
    """Los resultados del Rol 2 no están en la carpeta configurada."""


def carpeta_exports() -> Path:
    return Path(os.getenv("CTI_EXPORTS_DIR", "data/exports_10m")).resolve()


@lru_cache(maxsize=32)
def _leer_json(nombre: str, _marca: float) -> dict:
    return json.loads((carpeta_exports() / nombre).read_text(encoding="utf-8"))


def leer_json(nombre: str) -> dict:
    ruta = carpeta_exports() / nombre
    if not ruta.is_file():
        raise DatosNoDisponibles(f"No existe {nombre} en {carpeta_exports()}")
    return _leer_json(nombre, ruta.stat().st_mtime)  # se recarga solo si el archivo cambia


def leer_csv(nombre: str) -> list[dict]:
    ruta = carpeta_exports() / nombre
    if not ruta.is_file():
        raise DatosNoDisponibles(f"No existe {nombre} en {carpeta_exports()}")
    with ruta.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def a_camel(dato):
    """snake_case -> camelCase en todas las claves (contrato del frontend)."""
    if isinstance(dato, dict):
        return {re.sub(r"_([a-z0-9])", lambda m: m.group(1).upper(), str(k)): a_camel(v) for k, v in dato.items()}
    if isinstance(dato, list):
        return [a_camel(x) for x in dato]
    return dato


# ---------------------------------------------------------------- consultas
def resumen() -> dict:
    cal, a, b = leer_json("calidad_datos.json"), leer_json("ml_metrics_A_genericas.json"), leer_json("ml_metrics_B_dominio.json")
    reglas, camp, ant = leer_json("hallazgos_reglas.json"), leer_json("campanas.json"), leer_json("anticipacion.json")
    b_inc = next((x for x in ant["backtest_incidentes"] if x["campana"] == "CAMP-2026-004"), {})
    return {
        "privacy_mode": camp.get("privacy_mode"),
        "filas_analizadas": cal["firewall"]["filas"] + cal["sistema_medico"]["filas"],
        "calidad": {"firewall": cal["firewall"]["puntaje_calidad"], "sistema_medico": cal["sistema_medico"]["puntaje_calidad"],
                    "advertencias": cal["advertencias"]},
        "deteccion": {"reglas_ioa": reglas["incidentes_detectados_por_ioa"],
                      "ml_generico": a["incidentes_en_top_n"], "ml_dominio": b["incidentes_en_top_n"],
                      "hallazgos_por_regla": reglas["resumen_por_regla"]},
        "campanas": {"total": len(camp["campaigns"]),
                     "por_severidad": {s: sum(c["severity"] == s for c in camp["campaigns"]) for s in ("CRITICA", "ALTA", "MEDIA")}},
        "anticipacion": {"cuentas_riesgo_alto_o_critico": ant["riesgo_actual"]["cuentas_alto_o_critico"],
                         "horas_alerta_confirmada": ant["alertas_tempranas"]["horas_confirmadas"],
                         "horas_evaluadas": ant["alertas_tempranas"]["horas_evaluadas"],
                         "dias_anticipacion_incidente_b": b_inc.get("dias_de_anticipacion"),
                         "siguiente_fase_backtest": ant["backtest_siguiente_fase"]["aciertos_top3"]},
    }


def listar_campanas() -> list[dict]:
    pron = {p["campaign_code"]: p for p in leer_json("anticipacion.json")["pronostico_siguiente_fase"]}
    salida = []
    for c in leer_json("campanas.json")["campaigns"]:
        ligera = {k: v for k, v in c.items() if k not in ("hallazgos", "evidence_refs")}
        ligera["siguiente_fase"] = pron.get(c["campaign_code"], {}).get("siguientes_fases_probables", [])
        salida.append(ligera)
    return salida


def obtener_campana(codigo: str) -> dict | None:
    pron = {p["campaign_code"]: p for p in leer_json("anticipacion.json")["pronostico_siguiente_fase"]}
    for c in leer_json("campanas.json")["campaigns"]:
        if c["campaign_code"] == codigo:
            return {**c, "pronostico": pron.get(codigo)}
    return None


def linea_de_tiempo(codigo: str) -> list[dict] | None:
    """Hallazgos de la campaña ordenados en el tiempo (incluye ajuste de reloj de +12h si aplica)."""
    if obtener_campana(codigo) is None:
        return None
    reglas = leer_json("hallazgos_reglas.json")
    camp = obtener_campana(codigo)
    entidades = set(camp["iocs"]["source_ips"] + camp["iocs"]["actor_tokens"] + camp["iocs"]["account_tokens"])
    eventos = []
    for h in reglas["hallazgos_ioa"]:
        valores = set()
        for v in h["entidades"].values():
            valores.update(v if isinstance(v, list) else [v])
        if valores & entidades:
            eventos.append({"inicio": h["inicio"], "fin": h["fin"], "regla": h["regla"], "nombre": h["nombre"],
                            "severidad": h["severidad"], "descripcion": h["descripcion"],
                            "dataset": h["evidencia"]["dataset"], "filas_evidencia": h["evidencia"]["total_filas"],
                            "ajuste_reloj_12h": h.get("ajuste_reloj_12h", False)})
    return sorted(eventos, key=lambda e: e["inicio"])


def escenarios_ipe() -> dict:
    return leer_json("campanas.json")["escenarios_ipe"]


def anticipacion() -> dict:
    ant = leer_json("anticipacion.json")
    alertas = [a for a in leer_csv("alertas_tempranas.csv") if a.get("nivel_alerta") == "CONFIRMADA"]
    return {
        "principio": ant["principio"],
        "riesgo_cuentas": leer_csv("riesgo_cuentas.csv"),
        "alertas_confirmadas": alertas,
        "backtest_incidentes": ant["backtest_incidentes"],
        "pronostico_siguiente_fase": ant["pronostico_siguiente_fase"],
        "backtest_siguiente_fase": ant["backtest_siguiente_fase"],
    }


def listar_sigma() -> list[str]:
    carpeta = carpeta_exports() / "sigma"
    if not carpeta.is_dir():
        raise DatosNoDisponibles(f"No existe la carpeta sigma en {carpeta_exports()}")
    return sorted(p.name for p in carpeta.glob("*.yml") if NOMBRE_SIGMA_VALIDO.match(p.name))


def ruta_sigma(nombre: str) -> Path | None:
    """Solo devuelve archivos de la lista blanca: evita leer archivos fuera de la carpeta (path traversal)."""
    if not NOMBRE_SIGMA_VALIDO.match(nombre) or nombre not in listar_sigma():
        return None
    return carpeta_exports() / "sigma" / nombre


def ruta_stix() -> Path:
    ruta = carpeta_exports() / "aegishealth_stix21_bundle.json"
    if not ruta.is_file():
        raise DatosNoDisponibles("No existe el bundle STIX")
    return ruta


def contexto_para_llm() -> str:
    """ÚNICO texto que se le pasa a Ollama: resumen agregado y seudonimizado (nunca filas crudas)."""
    campanas = [{k: c[k] for k in ("campaign_code", "adversary_type", "severity", "summary", "first_seen", "last_seen")}
                | {"tecnicas": [t["id"] + " " + t["name"] for t in c["mitre_techniques"]], "ioas": c["ioas"]}
                for c in leer_json("campanas.json")["campaigns"]]
    return json.dumps({"resumen": resumen(), "campanas": campanas, "escenarios_ipe": escenarios_ipe()},
                      ensure_ascii=False)
```

## Anexo B — `app/api/rutas_cti.py`
```python
"""Rutas de inteligencia de amenazas (resultados del Rol 2). Respuestas en camelCase."""
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.servicios import inteligencia as cti

rutas_cti = APIRouter(prefix="/api/v1", tags=["Inteligencia de amenazas"])


def _seguro(funcion, *args):
    try:
        return funcion(*args)
    except cti.DatosNoDisponibles as error:
        raise HTTPException(status_code=503, detail=str(error)) from None


@rutas_cti.get("/dashboard/summary", summary="KPIs: calidad, detección, campañas y anticipación")
def resumen():
    return cti.a_camel(_seguro(cti.resumen))


@rutas_cti.get("/campaigns", summary="Campañas detectadas con MITRE ATT&CK y siguiente fase probable")
def campanas():
    return cti.a_camel({"campaigns": _seguro(cti.listar_campanas)})


@rutas_cti.get("/campaigns/{codigo}", summary="Detalle de una campaña con evidencia y pronóstico")
def campana(codigo: str):
    c = _seguro(cti.obtener_campana, codigo)
    if c is None:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    return cti.a_camel(c)


@rutas_cti.get("/campaigns/{codigo}/timeline", summary="Línea de tiempo de la campaña")
def linea_tiempo(codigo: str):
    t = _seguro(cti.linea_de_tiempo, codigo)
    if t is None:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    return cti.a_camel({"campaignCode": codigo, "eventos": t})


@rutas_cti.get("/ipe/escenarios", summary="Escenario más probable y más peligroso (IPE)")
def escenarios():
    return cti.a_camel(_seguro(cti.escenarios_ipe))


@rutas_cti.get("/anticipacion", summary="Riesgo previo por cuenta, alertas confirmadas y siguiente fase")
def anticipacion():
    return cti.a_camel(_seguro(cti.anticipacion))


@rutas_cti.get("/exports/sigma", summary="Lista de reglas Sigma")
def sigma():
    return {"reglas": _seguro(cti.listar_sigma)}


@rutas_cti.get("/exports/sigma/{nombre}", summary="Descargar una regla Sigma")
def sigma_archivo(nombre: str):
    ruta = _seguro(cti.ruta_sigma, nombre)
    if ruta is None:
        raise HTTPException(status_code=404, detail="Regla no encontrada")
    return FileResponse(ruta, media_type="application/x-yaml", filename=nombre)


@rutas_cti.get("/exports/stix", summary="Descargar bundle STIX 2.1 (importable en MISP)")
def stix():
    return FileResponse(_seguro(cti.ruta_stix), media_type="application/json",
                        filename="aegishealth_stix21_bundle.json")
```

## Anexo C — `tests/test_inteligencia.py`
```python
"""Pruebas del servicio de inteligencia (sin FastAPI). Ejecutar: python tests/test_inteligencia.py"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("CTI_EXPORTS_DIR", "data/exports_10m")
from app.servicios import inteligencia as cti  # noqa: E402

r = cti.resumen()
assert r["filas_analizadas"] > 10_000_000, r["filas_analizadas"]
assert r["deteccion"]["reglas_ioa"] == "5/5"
assert len(cti.listar_campanas()) == 5
assert cti.obtener_campana("CAMP-2026-001")["severity"] == "CRITICA"
assert cti.obtener_campana("NO-EXISTE") is None
assert len(cti.linea_de_tiempo("CAMP-2026-004")) >= 3
assert set(cti.escenarios_ipe()) >= {"ESCENARIO_MAS_PROBABLE", "ESCENARIO_MAS_PELIGROSO"}
assert len(cti.listar_sigma()) == 10
assert cti.ruta_sigma("../../.env") is None and cti.ruta_sigma("..%2Fsecreto.yml") is None   # path traversal bloqueado
assert "campaignCode" in cti.a_camel(cti.listar_campanas()[0])
ctx = cti.contexto_para_llm()
assert "XYZ" not in ctx and "MINAD" not in ctx and len(ctx) < 20_000
print("OK: todas las pruebas del servicio pasaron")
print(json.dumps(cti.a_camel(r), indent=2, ensure_ascii=False))
```
