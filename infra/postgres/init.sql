-- =============================================================================
-- AegisHealth-CTI — Esquema PostgreSQL 16 (cti_core y cti_audit)
-- Propósito: Almacenamiento analítico seudonimizado (LOPDP Art. 25),
--            bóveda aislada para Break-Glass y bitácora inmutable hash-chain.
-- Compatible estrictamente con postgres:16-alpine.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Esquemas aislados por dominio funcional y auditoría
CREATE SCHEMA IF NOT EXISTS cti_core;
CREATE SCHEMA IF NOT EXISTS cti_audit;

COMMENT ON SCHEMA cti_core IS 'Esquema analítico con métricas agregadas, eventos de alta señal y campañas seudonimizadas.';
COMMENT ON SCHEMA cti_audit IS 'Esquema de auditoría forense inmutable con encadenamiento criptográfico SHA-256.';

-- -----------------------------------------------------------------------------
-- 1. Métricas horarias base sobre el 100% de los 10,023,532 registros
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cti_core.baseline_hourly_metrics (
    metric_id        BIGSERIAL PRIMARY KEY,
    source_layer     VARCHAR(16) NOT NULL,
    event_hour       TIMESTAMPTZ NOT NULL,
    category         VARCHAR(64) NOT NULL,
    action_status    VARCHAR(32) NOT NULL,
    event_count      BIGINT NOT NULL,
    corrupt_ip_count INT DEFAULT 0
);

COMMENT ON TABLE cti_core.baseline_hourly_metrics IS 'Agregados horarios que resumen el 100% del volumen FW y MedSys sin almacenar filas crudas.';

-- -----------------------------------------------------------------------------
-- 2. Eventos de alta señal del Firewall (seudonimizados)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cti_core.fw_high_signal_events (
    event_id        BIGSERIAL PRIMARY KEY,
    event_ts        TIMESTAMPTZ NOT NULL,
    src_ip          INET NOT NULL,
    dst_ip_raw      VARCHAR(64) NOT NULL,
    dst_ip          INET NULL,
    was_dotless_ip  BOOLEAN NOT NULL DEFAULT FALSE,
    ip_reparable    BOOLEAN NOT NULL DEFAULT TRUE,
    is_external_ip  BOOLEAN NOT NULL DEFAULT FALSE,
    actor_token     VARCHAR(32) NOT NULL,
    dst_user_scope  VARCHAR(32) NOT NULL,
    application     VARCHAR(64) NOT NULL,
    dst_port        INT NOT NULL,
    protocol        VARCHAR(16) NOT NULL,
    action          VARCHAR(16) NOT NULL
);

COMMENT ON TABLE cti_core.fw_high_signal_events IS 'Subconjunto de eventos críticos o anómalos del Firewall con actores seudonimizados (USR-...).';

-- -----------------------------------------------------------------------------
-- 3. Eventos especiales no-SIM del Sistema Médico (14,501 filas)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cti_core.med_special_events (
    event_id          BIGSERIAL PRIMARY KEY,
    event_ts          TIMESTAMPTZ NOT NULL,
    account_token     VARCHAR(32) NOT NULL,
    actor_token       VARCHAR(32) NOT NULL,
    identidad_ambigua BOOLEAN DEFAULT FALSE,
    action_desc       VARCHAR(64) NOT NULL,
    conn_ip_raw       VARCHAR(64) NOT NULL,
    conn_ip           INET NULL,
    was_dotless_ip    BOOLEAN NOT NULL DEFAULT FALSE,
    ip_reparable      BOOLEAN NOT NULL DEFAULT TRUE,
    is_central_server BOOLEAN NOT NULL DEFAULT FALSE
);

COMMENT ON TABLE cti_core.med_special_events IS 'Registros de cuentas especiales no-SIM en MedSys con cuenta técnica (ACC-...) y actor (USR-...) seudonimizados.';

-- -----------------------------------------------------------------------------
-- 4. Bóveda aislada de cuentas técnicas (exclusivo Break-Glass; cero nombres PII)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cti_core.account_vault (
    account_token     VARCHAR(32) PRIMARY KEY,
    system_account_id VARCHAR(32) UNIQUE NOT NULL,
    created_at        TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE cti_core.account_vault IS 'Mapeo aislado ACC-XXXXXXXXXXXX hacia código de cuenta técnica para flujo Break-Glass; jamás almacena nombres humanos.';

-- -----------------------------------------------------------------------------
-- 5. Campañas de amenaza correlacionadas y metadatos MITRE / IPE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cti_core.threat_campaigns (
    campaign_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_code    VARCHAR(32) UNIQUE NOT NULL,
    title            VARCHAR(160),
    adversary_type   VARCHAR(32),
    severity         VARCHAR(16),
    ipe_scenario     VARCHAR(32),
    admiralty_rating VARCHAR(8),
    anomaly_score    NUMERIC(6,4) DEFAULT 0,
    event_count      INT DEFAULT 0,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    mitre_tactics    JSONB DEFAULT '[]'::jsonb,
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    iocs             JSONB DEFAULT '{}'::jsonb,
    ioas             JSONB DEFAULT '[]'::jsonb,
    summary_metrics  JSONB DEFAULT '{}'::jsonb
);

COMMENT ON TABLE cti_core.threat_campaigns IS 'Campañas consolidadas con taxonomía MITRE ATT&CK, evaluación IPE y calificación Admiralty.';

-- -----------------------------------------------------------------------------
-- 6. Línea de tiempo correlacionada FW <-> MedSys por campaña
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cti_core.campaign_timeline_events (
    timeline_id        BIGSERIAL PRIMARY KEY,
    campaign_code      VARCHAR(32) REFERENCES cti_core.threat_campaigns(campaign_code) ON DELETE CASCADE,
    event_ts           TIMESTAMPTZ NOT NULL,
    source_layer       VARCHAR(16) NOT NULL,
    actor_token        VARCHAR(32),
    account_token      VARCHAR(32),
    src_or_conn_ip     INET,
    dst_ip             INET,
    dst_port           INT,
    event_summary      TEXT,
    clock_skew_12h_fix BOOLEAN DEFAULT FALSE
);

COMMENT ON TABLE cti_core.campaign_timeline_events IS 'Secuencia cronológica correlacionada entre capas con marca explícita de ajuste horario +12h.';

-- -----------------------------------------------------------------------------
-- 7. Bitácora de auditoría inmutable con hash encadenado SHA-256
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cti_audit.audit_events (
    audit_id        BIGSERIAL PRIMARY KEY,
    executed_at     TIMESTAMPTZ DEFAULT NOW(),
    operation       VARCHAR(64) NOT NULL,
    dataset_name    VARCHAR(128),
    dataset_sha256  VARCHAR(64),
    total_rows_read BIGINT DEFAULT 0,
    rows_persisted  BIGINT DEFAULT 0,
    pii_scrubbed    BOOLEAN DEFAULT TRUE,
    metadata        JSONB DEFAULT '{}'::jsonb,
    prev_hash       VARCHAR(64) NOT NULL,
    row_hash        VARCHAR(64) NOT NULL
);

COMMENT ON TABLE cti_audit.audit_events IS 'Registro append-only con encadenamiento criptográfico prev_hash -> row_hash para cumplimiento LOPDP.';

-- -----------------------------------------------------------------------------
-- 8. Índices compuestos para consultas analíticas y correlación temporal
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_baseline_hour_layer
    ON cti_core.baseline_hourly_metrics (event_hour, source_layer);

CREATE INDEX IF NOT EXISTS idx_fw_high_actor_ts
    ON cti_core.fw_high_signal_events (actor_token, event_ts);

CREATE INDEX IF NOT EXISTS idx_fw_high_src_ip_ts
    ON cti_core.fw_high_signal_events (src_ip, event_ts);

CREATE INDEX IF NOT EXISTS idx_fw_high_port_proto
    ON cti_core.fw_high_signal_events (dst_port, protocol);

CREATE INDEX IF NOT EXISTS idx_med_special_actor_ts
    ON cti_core.med_special_events (actor_token, event_ts);

CREATE INDEX IF NOT EXISTS idx_med_special_account_ts
    ON cti_core.med_special_events (account_token, event_ts);

CREATE INDEX IF NOT EXISTS idx_timeline_campaign_ts
    ON cti_core.campaign_timeline_events (campaign_code, event_ts);

-- -----------------------------------------------------------------------------
-- 9. Rol de aplicación con permisos estrictos de inmutabilidad en auditoría
-- -----------------------------------------------------------------------------
\getenv app_user POSTGRES_APP_USER
\getenv app_password POSTGRES_APP_PASSWORD
SELECT :'app_user' = current_user AS mismo_rol,
       NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'app_user') AS crear_rol \gset
\if :mismo_rol
    DO $$ BEGIN RAISE EXCEPTION 'POSTGRES_APP_USER debe ser distinto de POSTGRES_USER'; END $$;
\endif
\if :crear_rol
    CREATE ROLE :"app_user" LOGIN PASSWORD :'app_password';
\endif
\unset app_password

GRANT USAGE ON SCHEMA cti_core TO :"app_user";
GRANT USAGE ON SCHEMA cti_audit TO :"app_user";

-- Permisos operativos sobre el esquema analítico cti_core
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA cti_core TO :"app_user";
REVOKE ALL PRIVILEGES ON TABLE cti_core.account_vault FROM :"app_user", PUBLIC;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA cti_core TO :"app_user";

-- Inmutabilidad estricta sobre auditoría: solo SELECT e INSERT (prohibido UPDATE/DELETE)
REVOKE ALL ON TABLE cti_audit.audit_events FROM :"app_user";
GRANT SELECT, INSERT ON TABLE cti_audit.audit_events TO :"app_user";
GRANT USAGE, SELECT ON SEQUENCE cti_audit.audit_events_audit_id_seq TO :"app_user";
