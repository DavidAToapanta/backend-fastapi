\set ON_ERROR_STOP on
\getenv app_user POSTGRES_APP_USER
\if :{?break_glass_password}
\else
    \getenv break_glass_password POSTGRES_BREAK_GLASS_PASSWORD
\endif
\if :{?break_glass_password}
    SELECT length(:'break_glass_password') > 0 AS configurar_break_glass \gset
\else
    \set configurar_break_glass false
\endif

BEGIN;

SELECT (:'app_user' = 'aegis_break_glass' OR current_user = 'aegis_break_glass')
       AS conflicto_roles_break_glass \gset
\if :conflicto_roles_break_glass
    DO $$ BEGIN RAISE EXCEPTION 'El rol Break-Glass debe ser independiente'; END $$;
\endif

REVOKE ALL PRIVILEGES ON TABLE cti_core.account_vault FROM :"app_user", PUBLIC;

\if :configurar_break_glass
    SELECT 'CREATE ROLE aegis_break_glass' WHERE NOT EXISTS (
        SELECT FROM pg_roles WHERE rolname = 'aegis_break_glass'
    ) \gexec
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM pg_auth_members
            WHERE 'aegis_break_glass'::regrole::oid IN (roleid, member)
        ) THEN
            RAISE EXCEPTION 'El rol Break-Glass debe quedar sin membresías';
        END IF;
    END $$;
    ALTER ROLE aegis_break_glass LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'break_glass_password';

    GRANT USAGE ON SCHEMA cti_core TO aegis_break_glass;
    REVOKE ALL PRIVILEGES ON TABLE cti_core.account_vault FROM aegis_break_glass;
    GRANT SELECT (account_token, system_account_id)
        ON TABLE cti_core.account_vault TO aegis_break_glass;
\endif

SELECT NOT has_any_column_privilege(:'app_user', 'cti_core.account_vault', 'SELECT')
       AND NOT has_table_privilege(:'app_user', 'cti_core.account_vault', 'INSERT,UPDATE,DELETE,TRUNCATE')
       AND has_table_privilege(:'app_user', 'cti_audit.audit_events', 'SELECT')
       AND has_table_privilege(:'app_user', 'cti_audit.audit_events', 'INSERT')
       AND NOT has_table_privilege(:'app_user', 'cti_audit.audit_events', 'UPDATE,DELETE,TRUNCATE')
       AS permisos_app_validos \gset
\if :permisos_app_validos
\else
    DO $ BEGIN RAISE EXCEPTION 'El rol de la API conserva permisos inesperados'; END $;
\endif

\if :configurar_break_glass
    SELECT has_column_privilege('aegis_break_glass', 'cti_core.account_vault', 'account_token', 'SELECT')
           AND has_column_privilege('aegis_break_glass', 'cti_core.account_vault', 'system_account_id', 'SELECT')
           AND NOT has_column_privilege('aegis_break_glass', 'cti_core.account_vault', 'created_at', 'SELECT')
           AND NOT has_table_privilege('aegis_break_glass', 'cti_core.account_vault', 'INSERT,UPDATE,DELETE,TRUNCATE')
           AND NOT has_table_privilege('aegis_break_glass', 'cti_audit.audit_events', 'SELECT,INSERT')
           AS permisos_boveda_validos \gset
    \if :permisos_boveda_validos
    \else
        DO $ BEGIN RAISE EXCEPTION 'El rol de investigación conserva permisos inesperados'; END $;
    \endif
\endif

COMMIT;
