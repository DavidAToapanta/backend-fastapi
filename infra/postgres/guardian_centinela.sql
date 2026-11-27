\set ON_ERROR_STOP on
\getenv app_user POSTGRES_APP_USER

BEGIN;
CREATE SCHEMA IF NOT EXISTS cti_piloto;

CREATE TABLE IF NOT EXISTS cti_piloto.reportes (
    id uuid PRIMARY KEY,
    reportante text NOT NULL,
    afiliado text,
    provincia text NOT NULL,
    recibido_en timestamptz NOT NULL DEFAULT clock_timestamp(),
    huella text NOT NULL,
    indicadores jsonb NOT NULL,
    UNIQUE (reportante, huella)
);

CREATE TABLE IF NOT EXISTS cti_piloto.eventos (
    id text PRIMARY KEY,
    datos jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS cti_piloto.casos (
    id uuid PRIMARY KEY,
    evidencia jsonb NOT NULL,
    estado text NOT NULL DEFAULT 'EN_REVISION'
        CHECK (estado IN ('EN_REVISION', 'CONFIRMADO', 'DESCARTADO')),
    decision_analista text,
    decision_motivo text,
    audit_id bigint REFERENCES cti_audit.audit_events (audit_id),
    creado_en timestamptz NOT NULL DEFAULT clock_timestamp()
);

GRANT USAGE ON SCHEMA cti_piloto TO :"app_user";
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA cti_piloto TO :"app_user";
GRANT UPDATE (evidencia, estado, decision_analista, decision_motivo, audit_id)
    ON cti_piloto.casos TO :"app_user";
COMMIT;
