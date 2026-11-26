# Motor de anticipación de amenazas (Rol 2) — resultados con 10.023.532 filas
**Para:** todo el equipo (Rol 4: pantalla · Rol 5: reporte, sección 7 "Evaluación de escenarios" y conclusiones)

## La idea en una frase
**No adivinamos la fecha de un ataque: lo anticipamos.** Con 5 incidentes en 31 días ningún modelo puede aprender
"cuándo" habrá un ataque sin sobreajustar (y revisamos día por día: ninguna señal sube antes de los ataques).
Lo que sí se puede, y está validado, son 3 niveles de anticipación:

| Nivel | Horizonte | Cómo funciona | Resultado validado (sin mirar el futuro) |
|---|---|---|---|
| 1. Riesgo previo por cuenta | Días o semanas antes | Cada día compara cada cuenta con lo normal del sistema (z robusto: mediana y MAD), usando solo datos hasta ese día | La cuenta del **incidente B ya estaba en riesgo CRÍTICO 16 días antes** (64 identidades distintas desde el 1-oct). Las cuentas del **incidente E, en riesgo alto desde el día 1**. 14 de 10.016 cuentas en riesgo alto o crítico, todas especiales |
| 2. Alerta temprana | La misma hora | Línea base de cada hora con los 7 días anteriores; CONFIRMADA si suben 2 o más señales a la vez o si ocurre algo nunca visto | **A, B, C y D alertados en la misma hora del ataque (0 horas de demora)**. 7 horas CONFIRMADAS en 744: 5 son los incidentes y 2 falsas alarmas |
| 3. Siguiente fase | Minutos | Cadena de Markov sobre las fases de MITRE ATT&CK: conocimiento experto + transiciones observadas (se recalibra con datos reales) | Prueba ocultando la última fase de cada campaña: **acierta 4 de 5** en su top 3. Cada predicción trae su control recomendado |

## Hallazgo clave para el jurado
En el incidente D, entre el acceso por SSH y la salida de datos a la IP externa pasaron **30 segundos**.
**Conclusión:** la respuesta tiene que ser **automática** (bloquear la salida no autorizada desde la red clínica).
Ningún analista humano alcanza a reaccionar en 30 segundos.

## Lo que NO se puede anticipar (y lo decimos)
Las cuentas de A, C y D **aparecen por primera vez el mismo día del ataque**: no hay historial que anticipar.
Por eso el sistema marca como NOVEDAD "una cuenta nueva que de repente es muy activa": se detecta en la misma hora.

## Por qué sirve con los datos reales del IESS (que serán distintos)
1. **Sin valores absolutos fijos:** el riesgo se mide contra lo normal de cada día ("cuántas veces se aleja de la mediana"), así que se adapta solo a otro volumen.
2. **Sin fuga de información:** todo se calcula con datos pasados (validación walk-forward).
3. **Aprende de la organización:** la matriz de fases parte de conocimiento experto y se ajusta con cada campaña real.
4. **Control de calidad a la entrada:** si aparecen columnas o valores nuevos, el sistema avisa antes de analizar (`calidad_datos.json`).
5. **Configurable sin tocar código:** umbrales en `config_rol2.json` (opción `--config`).
6. **Camino a un modelo predictivo real:** cuando el SOC acumule meses de incidentes etiquetados por analistas, se puede entrenar un modelo supervisado. Hoy sería sobreajuste.

## Archivos (carpeta exports_10m)
- `anticipacion.json`: todo lo anterior, incluido el backtest por incidente.
- `riesgo_cuentas.csv`: cuentas en riesgo ALTO o CRÍTICO con sus razones en español.
- `alertas_tempranas.csv`: hora, señal, valor, valor esperado, tipo (DESVIO o NOVEDAD) y nivel (AVISO o CONFIRMADA).
- `calidad_datos.json`: puntaje de calidad (firewall 99,99% · sistema médico 99,97%).

## Para Rol 4 (pantalla "Anticipación")
1. Tabla de `riesgo_cuentas.csv` con un color por nivel.
2. Línea de tiempo de 744 horas, marcando las alertas CONFIRMADAS.
3. Para cada campaña: "fase actual → siguientes fases probables (%) → control recomendado" (`pronostico_siguiente_fase`).
