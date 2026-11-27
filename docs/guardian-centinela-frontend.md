# Centinela y Guardián · Contrato para el Rol 4

Las rutas del piloto cuelgan de `http://127.0.0.1:8000/api/v1`. Vite puede conectarse desde `http://localhost:5173` o `http://127.0.0.1:5173`. El piloto usa identidades y operaciones sintéticas. El estado «Retenida» representa la decisión de la demo.

## Rutas y autenticación

| Método y ruta | Acceso | Respuesta |
|---|---|---|
| `POST /api/v1/centinela/reportes` | Bearer de sesión de demo | `201` si se creó o `200` si se reenvió |
| `GET /api/v1/centinela/campanas` | Consulta local | `200` con una lista de campañas |
| `POST /api/v1/guardian/evaluar` | Bearer de analista y `X-Analyst-Id` | `200` con `alerts`, `cases`, `evaluatedEvents` e `ignoredEvents` |
| `GET /api/v1/guardian/casos` | Bearer de analista y `X-Analyst-Id` | `200` con una lista de casos |
| `GET /api/v1/guardian/casos/{case_id}` | Bearer de analista y `X-Analyst-Id` | `200` con el caso |
| `POST /api/v1/guardian/casos/{case_id}/decision` | Bearer de analista y `X-Analyst-Id` | `200` con el caso resuelto |

Ingresá los tokens en la interfaz de demo y mantenelos en memoria. El mismo formulario admite el token de la sesión afiliada o de una sesión anónima. El servidor determina a qué afiliado corresponde cada sesión. El listado de provincias y los modelos completos se pueden consultar en `/openapi.json`.

### Reportar y actualizar el mapa

```js
const api = "http://127.0.0.1:8000/api/v1";

const respuesta = await fetch(api + "/centinela/reportes", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Authorization: "Bearer " + sesionToken,
  },
  body: JSON.stringify({
    text: "Mensaje de prueba https://alerta.example y cuenta 2200123456",
    province: "Pichincha",
  }),
});

if (!respuesta.ok) throw new Error((await respuesta.json()).detail);
const reporte = await respuesta.json();
```

La respuesta incluye `reportId`, `province`, `receivedAt`, `summary` e `indicators` con listas `domains`, `phones` y `accounts`. Usá el resumen generado para la confirmación. Mostrá los dominios como texto.

Al actualizar `/centinela/campanas`, cada elemento contiene `campaignId`, `reportCount`, `byProvince`, `domains` y `status`. Una campaña empieza en `EN_OBSERVACION`. Desde tres reportantes distintos pasa a `AVISO_A_AFILIADOS`. Mostrá ese aviso como simulación. El primer reporte de cada reportante en la campaña define su provincia para el conteo. Si dos grupos se fusionan por un indicador común, la campaña usa el identificador del reporte más antiguo del grupo combinado.

### Evaluar y decidir

```js
const headers = {
  Authorization: "Bearer " + analystToken,
  "X-Analyst-Id": analystId,
};

const evaluacion = await fetch(api + "/guardian/evaluar", { method: "POST", headers });
if (!evaluacion.ok) throw new Error((await evaluacion.json()).detail);
const { alerts, cases } = await evaluacion.json();

const caso = cases.find(({ evidence }) => evidence.rule === "GUARD-01");
if (caso?.status === "EN_REVISION") {
  // Ejecutar este POST desde el botón «Confirmar».
  const respuesta = await fetch(api + "/guardian/casos/" + caso.caseId + "/decision", {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify({ decision: "CONFIRMAR", reason: "Evidencia del ejercicio revisada." }),
  });
  if (!respuesta.ok) throw new Error((await respuesta.json()).detail);
  const resuelto = await respuesta.json();
  console.log(resuelto.status, resuelto.auditId);
}
```

- Las alertas contienen `rule`, `severity`, `confidence`, `action`, `explanation`, `timeline` y, cuando hay una coincidencia, `phishingLink` y `phishingReportId`. Cada paso tiene `eventId`, `timestamp`, `event` y `channel`. Usá `caseId` para abrir un caso. Es `null` en alertas informativas.
- Un caso incluye `caseId`, `status`, `operationStatus`, `evidence`, `createdAt` y `simulated`. Tras la decisión incluye `auditId`, `decidedBy` y `decisionReason`. El estado pasa de `EN_REVISION` a `CONFIRMADO` o `DESCARTADO`. La operación simulada queda `RETENIDA` o `LIBERADA`.
- La decisión admite `CONFIRMAR` o `DESCARTAR` y un motivo de 10 a 300 caracteres. El reenvío idéntico del mismo analista devuelve el `auditId` anterior.
- Mostrá el campo `detail` cuando falle una solicitud. `401` indica credencial inválida, `404` caso inexistente, `409` decisión incompatible con un caso resuelto, `422` campos inválidos o reporte sin indicadores y `503` módulo indisponible. Ante `409`, volvé a consultar el caso.

## Preparación local y recorrido de la demo

En PowerShell, desde la raíz del backend:

```powershell
.\scripts\preparar_piloto.ps1
$directorio = Join-Path $env:LOCALAPPDATA 'AegisHealth\guardian-piloto'
$envPiloto = Join-Path $directorio 'piloto.env'
$compose = @('compose','--env-file','.env','--env-file',$envPiloto,'-f','infra/docker-compose.yml')

# Con PostgreSQL ya iniciado, aplicar la migración al volumen existente.
Get-Content -Raw infra/postgres/guardian_centinela.sql |
    docker @compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
if ($LASTEXITCODE) { throw 'Falló la migración del piloto.' }
docker @compose up -d --no-deps --build backend
```

Las credenciales del ejercicio quedan en `credenciales.json` dentro de `$directorio`. `affiliateToken` corresponde al caso crítico. Los dos tokens anónimos permiten alcanzar el umbral del mapa en la demo. `analystId` y `analystToken` sirven para las rutas de Guardián.

1. Enviá el ejemplo desde la sesión afiliada. Reenvialo y confirmá que el segundo POST devuelve el mismo `reportId`. Con las dos sesiones anónimas, enviá el mismo dominio desde dos provincias adicionales y comprobá el contador del mapa.
2. Después del reporte, cargá los escenarios en un entorno de demo vacío. El comando registra 21 eventos y conserva sus IDs al repetirse. El caso crítico se ubica a partir de la hora de la carga y representa una secuencia simulada de 40 minutos.

   ```powershell
   docker @compose exec -T backend python -m app.datos_demo.cargar_guardian
   ```

3. Evaluá desde la sesión del analista. Se esperan seis alertas y dos casos en revisión. La alerta crítica debe referenciar el `reportId` recibido en el primer paso. La alerta baja biométrica aparece sin caso.
4. Confirmá un caso y descartá el otro. Consultá `GET /api/v1/audit/events` para cruzar los `auditId` con la operación `GUARDIAN_CASE_DECISION`. Consultá `GET /api/v1/audit/verify-chain` y verificá `intact: true`.

Para repetir la historia desde cero, usá una base de ensayo nueva con la misma migración. El `PILOTO_TEST_DSN` de las pruebas de integración apunta a una base vacía de ensayo llamada `guardian_pruebas`, con el esquema base y la migración ya aplicados.
