# Cierre del Rol 3

## Preparar la laptop #6

Desde la raíz del backend, comprueba que `.env` apunta a la exportación del Rol 2 mediante `METRICAS_ML_DIR_HOST` y que Ollama nativo tiene `qwen3:4b`. Compose publica la API en `127.0.0.1:8000` y guarda la caché F-11 en el volumen `cache_f11`.

```powershell
docker compose --env-file .env -f infra/docker-compose.yml up -d --build
docker compose --env-file .env -f infra/docker-compose.yml exec -T backend python -m app.cti_exports.cache_f11
```

La caché guarda conclusiones generadas localmente y una huella de los agregados y el contenido del reporte. Si cambian los insumos, vuelve a generarla. Si el modelo falla, la caché anterior queda disponible para sus insumos originales. El listado de campañas y las exportaciones del Rol 2 se mantienen en solo lectura.

El informe técnico `Reporte_CTI_Tecnico_F11_AegisHealth.pdf` incorpora en portada la Sección 0 de resumen BLUF (TLP:AMBER). Tras la validación editorial final, marca esa caché validada con el siguiente comando; al regenerar conclusiones vuelve al estado de edición técnica generada (sin sellos provisionales).

```powershell
docker compose --env-file .env -f infra/docker-compose.yml exec -T backend python -m app.cti_exports.cache_f11 --aprobar
```

## Contratos para el Rol 4

- `POST /api/v1/llm/regenerate-section` con `Content-Type: application/json` y cuerpo `{"section":"conclusions"}`. Devuelve `{"section":"conclusions","text":"…"}`. Durante la inferencia, muestra un indicador de carga. Usa `text` como texto de interfaz. Ollama selecciona el enfoque del análisis y la API incorpora solo cifras verificadas. La acción de la demo conserva la caché del PDF. Una sección inválida da `422` y una dependencia local caída da `503`.
- `POST /api/v1/reports/generate-pdf` acepta `{"audience":"technical","format":"F-11"}` o `{"audience":"medical","format":"EJECUTIVO_MEDICO"}` según el rol de la interfaz. Un POST sin cuerpo genera el F-11. El campo opcional `summary` se imprime solo en el F-11. Lee el PDF como blob y el nombre de `Content-Disposition`. El encabezado `X-Audit-Id` identifica el evento `EXPORT_TECHNICAL_F11_PDF` o `EXPORT_MEDICAL_PDF` y `X-Report-SHA256` contiene la huella del archivo. Un formato incompatible da `422`. Ante `503`, muestra que el informe aún no está disponible.
- `POST /api/v1/audit/reveal` con `Authorization: Bearer …` y cuerpo `{"analystId":"demo-rol3","reason":"Validación de la demo","accountToken":"ACC-…"}`. Usa el token de la cuenta seleccionada. Mantén `technicalAccount` en memoria hasta cerrar el modal, cambiar de campaña o pulsar «Ocultar».
- Vite puede usar `http://localhost:5173` o `http://127.0.0.1:5173`. Conserva todas las rutas de estado, panel, campañas, exportaciones y auditoría documentadas en `/docs`.

## Ensayo final

Con el frontend preparado, ejecuta `pip-audit` antes de desconectar la red. Registra la auditoría de partida. Desconecta Wi‑Fi y Ethernet externos en la #6 y verifica desde el frontend que PostgreSQL y Ollama siguen disponibles con `zeroEgress: true`. Recorre el panel, la cronología, las descargas Sigma y STIX, un rechazo de Break-Glass y una revelación autorizada seguida de ocultamiento. Regenera las conclusiones y mide la descarga del PDF revisado de extremo a extremo. Debe tardar menos de 15 segundos. Revisa que se agregue un evento por la revelación y otro por el PDF, que coincida la huella del archivo y que la cadena siga íntegra. Entrega el PDF revisado, Sigma, STIX y el resultado al Rol 5.
