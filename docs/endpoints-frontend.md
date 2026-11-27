# AegisHealth-CTI · Endpoints para conectar y probar el frontend

**Para el Rol 4.** El backend expone 12 consultas `GET` y 3 acciones `POST`. Para probar la conexión, abrí el frontend en `http://localhost:5173` en la misma laptop que ejecuta FastAPI. Desde la consola del navegador, esta llamada debe devolver `{status: "healthy"}`:

```js
await (await fetch("http://127.0.0.1:8000/health")).json()
```

## Conexión desde Vite

Usá `http://127.0.0.1:8000` como base. En otra laptop, esa dirección apunta a la propia máquina. FastAPI permite los orígenes `http://localhost:5173` y `http://127.0.0.1:5173`. Si Vite cambia de puerto, arrancalo con `npm run dev -- --port 5173 --strictPort`. Si el proyecto tiene mocks, desactivalos para esta prueba.

El siguiente módulo sirve para los ejemplos de esta guía. Guardalo en el frontend como `src/api.js`. La función `request` conserva la respuesta completa para las descargas. La función `json` lee el cuerpo de las consultas y acciones que devuelven JSON.

```js
const base = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export async function request(path, options = {}) {
  const response = await fetch(base + path, options);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const message = typeof body.detail === "string" ? body.detail : "Revisá los campos enviados.";
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return response;
}

export async function json(path, options) {
  return (await request(path, options)).json();
}

export function postJson(body, headers = {}) {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  };
}
```

Si ya usás un proxy de Vite para `/api`, podés llamar a las rutas `/api/v1/…` con `fetch` relativo. Las dos comprobaciones `/` y `/health` se consultan en la dirección del backend. Todas las rutas del catálogo carecen de parámetros de consulta. Solo Break-Glass requiere credencial.

## Catálogo completo

Todas las respuestas exitosas tienen estado `200`. En un error, FastAPI devuelve JSON con `detail`. Para `422`, el detalle puede ser una lista con la ubicación y la causa de cada error de validación.

| Método y ruta | Dónde usarlo | Respuesta exitosa | Otros estados previstos |
|---|---|---|---|
| `GET /` | Comprobar la dirección de la API | `{"status":"ok","message":"Backend funcionando"}` | — |
| `GET /health` | Comprobar que FastAPI responde | `{"status":"healthy"}` | — |
| `GET /api/v1/health` | Indicadores de servicios | `postgresReady`, `ollamaReady` y `zeroEgress`, los tres booleanos | Puede devolver `200` con servicios caídos |
| `GET /api/v1/dashboard/summary` | Tarjetas del panel y comparación ML | Totales, desglose por fuente, seudonimización y métricas ML | `503` |
| `GET /api/v1/analytics/hourly-heatmap` | Mapa de calor | `timezone`, `days`, `hours`, `matrix` | `503` |
| `GET /api/v1/campaigns` | Selector de campañas y escenarios IPE | `campaigns[]`, `ipeScenarios[]` | `503` |
| `GET /api/v1/campaigns/{code}/timeline` | Cronología de la campaña seleccionada | `campaignCode`, `events[]` | `404` código desconocido, `503` |
| `GET /api/v1/exports/sigma` | Listar, visualizar o guardar reglas YAML | `ioa[]` e `ioc[]`, cada regla con `filename`, `title`, `yaml` | `503` |
| `GET /api/v1/exports/stix` | Descargar el paquete de inteligencia | Archivo `application/stix+json; version=2.1` con `Content-Disposition` | `503` |
| `GET /api/v1/audit/events` | Bitácora | `events[]`, del más reciente al más antiguo | `503` |
| `GET /api/v1/audit/verify-chain` | Verificar integridad | `intact` booleano y `checkedRows` entero | `503` |
| `POST /api/v1/audit/reveal` | Revelar una cuenta técnica desde un modal | `accountToken`, `technicalAccount` y `auditId` | `401`, `404`, `422`, `503` |
| `POST /api/v1/llm/regenerate-section` | Botón «Regenerar conclusiones» | `section` y `text` | `422`, `503` |
| `POST /api/v1/reports/generate-pdf` | Descargar informe técnico o médico | Archivo `application/pdf` con nombre, ID de auditoría y SHA-256 en cabeceras | `422`, `503` |
| `GET /api/v1/misp/estado` | Tarjeta «Última carga verificada en MISP» | `lastVerifiedAt`, `eventCount`, `distribution`, `exports[]` | `503` si falta un resumen válido |

Para inspeccionar tipos y campos en la versión que está corriendo, abrí [Swagger UI](http://127.0.0.1:8000/docs), [ReDoc](http://127.0.0.1:8000/redoc) o el [contrato OpenAPI en JSON](http://127.0.0.1:8000/openapi.json). Las interfaces de documentación pueden requerir recursos de internet. FastAPI también registra `/docs/oauth2-redirect` como ruta auxiliar de Swagger.

## Qué leer en cada pantalla

**Panel.** Mostrá `totalEvents`, `malformedIpEvents` y `hoursCovered`. Cada elemento de `bySource` trae `source` (`FIREWALL` o `MEDSYS`), `events` y `malformedIpEvents`. `pseudonymizationRecorded` puede ser `true`, `false` o `null`; para `null`, usá «Sin evidencia de ingesta». En `ml.generic` y `ml.domain` cada bloque disponible contiene `incidentsInTopN` (texto como `4/5`), `topN` y `unconfirmedAnomalies` con `firewallHourly`, `medsysHourly` y `medsysByPeriod`. Cualquiera de los dos bloques ML puede ser `null`. El indicador `zeroEgress` significa que falló la prueba TCP saliente del backend; `ollamaReady` informa si responde el servicio local.

**Mapa horario.** `timezone` es `UTC`. Cada fila corresponde a una hora y cada columna a una fecha. El valor para `hours[h]` y `days[d]` es `matrix[h][d]`. Conservá las fechas del eje tal como llegan para evitar que la conversión a hora local las desplace al día anterior.

**Campañas.** Cada ficha trae `campaignCode`, `title`, `adversaryType`, `severity`, `admiraltyRating`, `anomalyScore`, `eventCount`, `firstSeen`, `lastSeen`, `mitreTechniques[]`, `ioas[]` e `iocs`. En `iocs` están `ports[]`, `sourceIps[]`, `destinationIps[]`, `actorTokens[]` y `accountTokens[]`. Los escenarios contienen `code`, `name`, `campaignCodes[]`, `description` e `hypothesis`. Mostrá «Sin dato» para valores escalares nulos; conservá el cero cuando venga informado.

**Cronología.** Usá el `campaignCode` recibido del catálogo. Cada evento trae `id`, `timestamp`, `source`, `summary`, `actorToken`, `accountToken`, `sourceIp`, `destinationIp`, `destinationPort` y `clockSkewAdjusted`. Los dos carriles son `FIREWALL` y `MEDSYS`. El indicador de ajuste describe la hora entregada por el backend. Una lista vacía es un resultado válido. Ejemplo desde un componente que importa el módulo anterior:

```js
import { json } from "./api.js";

const { campaigns } = await json("/api/v1/campaigns");
const selected = campaigns[0];
if (selected) {
  const code = encodeURIComponent(selected.campaignCode);
  const { events } = await json("/api/v1/campaigns/" + code + "/timeline");
  console.log(selected.campaignCode, events.length);
}
```

**Auditoría.** Cada registro contiene `auditId`, `executedAt`, `operation`, `datasetName`, `datasetSha256`, `totalRowsRead`, `rowsPersisted`, `piiScrubbed` y `rowHash`. La respuesta de verificación puede ser `200` con `intact: false`. Mostrá el resultado del campo y la cantidad de filas verificadas.

**MISP.** Mostrá la fecha de `lastVerifiedAt` y el conteo de `eventCount` como última carga comprobada. `exports` enumera nombres de archivos. La API lee el resumen en disco y puede devolver `200` con MISP apagado. Para `503`, mostrá «Carga MISP pendiente de verificación» y mantené disponibles el panel, Sigma y STIX.

## Las tres acciones POST

### Revelar una cuenta técnica

Enviar `Authorization: Bearer <clave del analista>` y un cuerpo JSON con `analystId`, `reason` y `accountToken`. El analista debe coincidir con el de la clave, el motivo debe tener al menos 10 caracteres después de quitar espacios, y el token debe ser `ACC-` seguido de 12 dígitos hexadecimales. Tomalo de `iocs.accountTokens` o del evento seleccionado.

```js
import { json, postJson } from "./api.js";

export function revelarCuenta(analystId, reason, accountToken, clave) {
  return json("/api/v1/audit/reveal", postJson(
    { analystId, reason, accountToken },
    { Authorization: "Bearer " + clave },
  ));
}
```

La respuesta lleva `Cache-Control: no-store`. Conservá `technicalAccount` y la clave únicamente en memoria y borrá el valor revelado al cerrar el modal, ocultarlo o cambiar de campaña. Una revelación autorizada genera un evento de auditoría. `401` indica credencial inválida o ausente, `404` cuenta desconocida, `422` datos inválidos y `503` servicio de investigación no disponible.

### Regenerar conclusiones

```js
import { json, postJson } from "./api.js";

const { text } = await json("/api/v1/llm/regenerate-section", postJson({
  section: "conclusions",
}));
```

Usá `text` en la vista y mostrá un estado de carga mientras responde Ollama. La solicitud admite únicamente el campo `section` con el valor `conclusions`. Para incluir ese texto como nota en el PDF técnico, envialo después como `summary` en la solicitud de descarga.

### Descargar el informe técnico o médico

| Selección de la interfaz | Cuerpo JSON | Archivo esperado |
|---|---|---|
| Técnico F-11 | `{"audience":"technical","format":"F-11"}` | `Reporte_CTI_Tecnico_F11_AegisHealth.pdf` |
| Ejecutivo médico | `{"audience":"medical","format":"EJECUTIVO_MEDICO"}` | `Reporte_Ejecutivo_Medico_AegisHealth.pdf` |

El POST sin cuerpo genera el técnico. `format` es opcional y debe corresponder a la audiencia si se envía. El campo opcional `summary` se imprime solo en el técnico. Una combinación incompatible devuelve `422`. Cada descarga exitosa registra `EXPORT_TECHNICAL_F11_PDF` o `EXPORT_MEDICAL_PDF`. Evitá enviar dos veces la solicitud mientras hay una descarga en curso.

Este ejemplo descarga el PDF desde el botón y devuelve los metadatos para enlazarlo con la bitácora. El mismo helper sirve para el archivo STIX.

```js
import { request, postJson } from "./api.js";

async function guardarArchivo(response, nombreAlternativo) {
  const disposition = response.headers.get("Content-Disposition") || "";
  const nombre = disposition.match(/filename="([^"]+)"/i)?.[1] || nombreAlternativo;
  const url = URL.createObjectURL(await response.blob());
  const enlace = document.createElement("a");
  enlace.href = url;
  enlace.download = nombre;
  document.body.appendChild(enlace);
  enlace.click();
  enlace.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function descargarPdf(audience, summary) {
  const body = audience === "medical"
    ? { audience, format: "EJECUTIVO_MEDICO" }
    : { audience: "technical", format: "F-11", summary };
  const response = await request("/api/v1/reports/generate-pdf", postJson(body));
  await guardarArchivo(response, "reporte.pdf");
  return {
    auditId: response.headers.get("X-Audit-Id"),
    sha256: response.headers.get("X-Report-SHA256"),
  };
}

export async function descargarStix() {
  const response = await request("/api/v1/exports/stix");
  await guardarArchivo(response, "aegishealth_stix21_bundle.json");
}
```

## Recorrido de prueba con el frontend

1. **Conexión.** Abrí el frontend en el puerto 5173 con los mocks desactivados. En DevTools → Red, confirmá `200` en `/health` y consultá `/api/v1/health` para conocer el estado de las dependencias.
2. **Panel.** Cargá el resumen y el mapa en paralelo. Contrastá una celda con `matrix[h][d]` en la respuesta. Si una consulta falla, mantené visibles los bloques que sí cargaron.
3. **Campaña.** Elegí una ficha y verificá que el código de la URL de la cronología coincide con la selección. Un código desconocido debe dar `404`. Si una cuenta está disponible, probá Break-Glass una vez sin clave con un cuerpo válido (`401`) y luego con una credencial autorizada. Comprobá que «Ocultar» limpia el valor.
4. **Artefactos.** Abrí el YAML de una regla Sigma y descargá el STIX. El JSON descargado debe contener `type: "bundle"` y una lista `objects`. Verificá que una respuesta `503` de MISP quede limitada a su tarjeta.
5. **Informes.** Regenerá las conclusiones. Descargá una vez cada audiencia y abrí los dos PDF. Contrastá el nombre y `X-Audit-Id` con la fila correspondiente en la bitácora. Volvé a consultar `/api/v1/audit/verify-chain`.
6. **Validación de errores.** Probá `{"section":"otra"}` en conclusiones y `{"audience":"medical","format":"F-11"}` en PDF. Ambos deben responder `422`. Mostrá el error en la acción correspondiente.

**Comprobación de esta entrega.** En la consulta directa al servidor local, 11 de los 12 GET devolvieron `200`. La ruta de MISP devolvió `503`. La solicitud previa CORS para Break-Glass desde `http://localhost:5173` devolvió `200`. Los pasos POST anteriores quedan disponibles para el ensayo interactivo del frontend.
