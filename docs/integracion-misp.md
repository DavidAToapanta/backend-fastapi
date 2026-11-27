# Ensayo local MISP y contrato para Rol 4

El publicador lee las campañas, la anticipación y las reglas Sigma del Rol 2. Usa una copia de la exportación que incluya el archivo oficial `iocs_ejercicio.json`. La versión ensayada procede del commit `6f41da79120343f598e96034019661d95bfee0f7` de `feat/ml-cti`, objeto Git `35bdb23f2c0fad01fefb89d6f3ebc27876626426`.

## Prueba sin MISP

Desde la raíz del backend, en PowerShell, definir `$insumos` con la ruta a la copia de ensayo.

```powershell
$env:MISP_EXPORTS_PRUEBA = $insumos
.\venv\Scripts\python.exe -m pytest -q tests/test_misp.py
.\venv\Scripts\python.exe -m app.integraciones.misp_publicador --exports "$insumos" --simular
```

La simulación genera `misp/eventos_simulados.json`. El script original armaba 38 atributos. Uno repetía el destino clínico de CAMP-002 y dos lo añadían a CAMP-003 y CAMP-004 por tener tráfico de red. La integración arma **35 atributos**. El servidor clínico figura en CAMP-001, respaldado por el salto SSH del incidente D en la evidencia del Rol 1, y en CAMP-002, donde figura entre los destinos observados.

## Instancia real

El ensayo usa el proyecto `aegis-misp-ensayo` con credenciales propias en el perfil local de Windows. Los servicios de MISP quedan en una red interna. Solo el proxy usa una segunda red para publicar HTTPS en `127.0.0.1:8443`. El catálogo se inicializa en un volumen de Docker para evitar copiar miles de archivos al sistema de archivos de Windows en el primer arranque. El preparador utiliza la plantilla del repositorio oficial de MISP, genera credenciales la primera vez y verifica la configuración resultante. La descarga inicial de imágenes requiere conexión. [MISP Docker](https://github.com/MISP/misp-docker)

```powershell
.\scripts\preparar_misp.ps1
$instancia = Join-Path $env:LOCALAPPDATA 'AegisHealth\misp-ensayo'
$compose = @('compose','-p','aegis-misp-ensayo','--project-directory',$instancia,'--env-file',"$instancia\.env",'-f',"$instancia\docker-compose.yml",'-f',"$PWD\scripts\misp-local.yml")
docker @compose pull
docker @compose up -d --wait --wait-timeout 1800
```

Antes de iniciar, comprobar la memoria disponible de Windows y WSL2. La guía del equipo estima 3–6 GiB de consumo y pide más de 8 GiB disponibles en WSL2. Revisar los servicios con `docker @compose ps`. Abrir la interfaz local, comprobar que no existen servidores de sincronización ni feeds habilitados y que TLP y la galaxia MITRE ATT&CK están cargados. El certificado generado tiene alcance local. El publicador lo verifica sin instalarlo en el almacén de confianza del sistema.

```powershell
$env:MISP_URL = 'https://127.0.0.1:8443'
$env:MISP_VERIFY_SSL = "$instancia\ssl\cert.pem"
$env:MISP_API_KEY = ((Get-Content -LiteralPath "$instancia\.env" | Where-Object { $_ -match '^ADMIN_KEY=' }) -split '=',2)[1]
try {
    .\venv\Scripts\python.exe -m app.integraciones.misp_publicador --exports "$insumos"
    if ($LASTEXITCODE) { throw 'La carga no está verificada. Revisar los IDs registrados.' }
} finally { Remove-Item Env:MISP_API_KEY }
```

Abrir los seis eventos y sus informes, la matriz MITRE y la relación entre CAMP-001 y CAMP-002. Comprobar las tres exportaciones. Los eventos y las reglas son datos de ejercicio. Si una ejecución se corta, los IDs impresos permiten identificar los eventos ya creados. La repetición se detiene antes de modificar los eventos existentes. Para repetir una carga parcial usar otra instancia de ensayo vacía con su propia carpeta y proyecto Compose. El plazo acordado es 45 minutos para instalar y 20 más para verificar la carga. El entregable de respaldo es el STIX original del Rol 2.

## FastAPI con MISP apagado

Tras la verificación, transferir únicamente `misp/misp_publicacion.json` de la copia de ensayo a la carpeta host montada en `METRICAS_ML_DIR`, conservando la subcarpeta `misp`. Para sustituir un resumen existente, copiar primero con nombre temporal en el mismo directorio y renombrar de forma atómica. El backend lee la carpeta en modo de solo lectura. Detener MISP con `docker @compose stop` conserva sus volúmenes.

`GET /api/v1/misp/estado` devuelve `lastVerifiedAt` (fecha ISO 8601 con zona horaria), `eventCount` (6), `distribution` y `exports` (CSV, reglas Suricata y STIX). El texto de pantalla sugerido es «Última carga verificada en MISP: 6 eventos». Si falta el resumen, está incompleto o solo se ha simulado la carga, devuelve HTTP 503. El estado describe la última carga y sigue disponible con MISP apagado.

Completar el ensayo del [cierre del Rol 3](cierre-rol-3.md) con los servicios y las evidencias reales en la laptop de la demo. Verificar el estado de MISP, panel, campañas, exportaciones, Break-Glass, bitácora y tiempo del PDF.
