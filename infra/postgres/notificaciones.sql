\set ON_ERROR_STOP on
\getenv app_user POSTGRES_APP_USER

BEGIN;

CREATE TABLE IF NOT EXISTS cti_piloto.notificaciones (
    id uuid PRIMARY KEY,
    origen text NOT NULL CHECK (origen IN ('GUARDIAN', 'CENTINELA')),
    referencia uuid NOT NULL,
    creado_en timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (origen, referencia)
);

CREATE TABLE IF NOT EXISTS cti_piloto.notificaciones_leidas (
    notificacion_id uuid NOT NULL REFERENCES cti_piloto.notificaciones (id),
    analista text NOT NULL,
    leido_en timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (notificacion_id, analista)
);

CREATE TABLE IF NOT EXISTS cti_piloto.cola_correo (
    notificacion_id uuid PRIMARY KEY REFERENCES cti_piloto.notificaciones (id),
    intentos integer NOT NULL DEFAULT 0,
    estado text NOT NULL DEFAULT 'PENDIENTE' CHECK (estado IN ('PENDIENTE', 'PROCESANDO', 'ENVIADO', 'FALLIDO')),
    siguiente_intento timestamptz NOT NULL DEFAULT clock_timestamp(),
    reclamo uuid,
    vence_reclamo timestamptz,
    enviado_en timestamptz,
    ultimo_error text
);

ALTER TABLE cti_piloto.notificaciones DROP CONSTRAINT IF EXISTS notificaciones_origen_check;
ALTER TABLE cti_piloto.notificaciones ADD CONSTRAINT notificaciones_origen_check
    CHECK (origen IN ('GUARDIAN', 'CENTINELA', 'DEMO'));

CREATE INDEX IF NOT EXISTS notificaciones_recientes_idx
    ON cti_piloto.notificaciones (creado_en DESC, id DESC);
CREATE INDEX IF NOT EXISTS cola_correo_pendiente_idx
    ON cti_piloto.cola_correo (siguiente_intento, notificacion_id)
    WHERE estado IN ('PENDIENTE', 'PROCESANDO');

GRANT SELECT, INSERT ON cti_piloto.notificaciones, cti_piloto.notificaciones_leidas TO :"app_user";
GRANT SELECT, INSERT, UPDATE ON cti_piloto.cola_correo TO :"app_user";

COMMIT;
