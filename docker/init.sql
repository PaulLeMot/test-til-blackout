-- Создаем пользователя admin если не существует
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'admin') THEN
        CREATE USER admin WITH PASSWORD 'admin' CREATEDB;
        RAISE NOTICE 'User admin created';
    ELSE
        RAISE NOTICE 'User admin already exists';
    END IF;
END
$$;

-- Создаем базу данных security_scanner если не существует
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'security_scanner') THEN
        PERFORM dblink_exec('dbname=postgres', 'CREATE DATABASE security_scanner');
        RAISE NOTICE 'Database security_scanner created';
    ELSE
        RAISE NOTICE 'Database security_scanner already exists';
    END IF;
END
$$;

-- Даем права пользователю admin на базу данных security_scanner
GRANT ALL PRIVILEGES ON DATABASE security_scanner TO admin;

-- Подключаемся к базе security_scanner и создаем таблицы
\c security_scanner;

-- Даем права на схему public в security_scanner
GRANT ALL ON SCHEMA public TO admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO admin;

-- Создаем таблицы
CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    bank_name VARCHAR(500) NOT NULL,
    vulnerability_title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    category VARCHAR(100) NOT NULL,
    status_code VARCHAR(10),
    proof TEXT,
    recommendation TEXT,
    scanner_name VARCHAR(200),
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scan_session_id VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    session_id VARCHAR(100) PRIMARY KEY,
    session_name VARCHAR(500) NOT NULL,
    banks_count INTEGER DEFAULT 0,
    vulnerabilities_count INTEGER DEFAULT 0,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    status VARCHAR(20) DEFAULT 'COMPLETED',
    config_json TEXT
);

-- Создаем индексы
CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_results(scan_date);
CREATE INDEX IF NOT EXISTS idx_severity ON scan_results(severity);
CREATE INDEX IF NOT EXISTS idx_category ON scan_results(category);
CREATE INDEX IF NOT EXISTS idx_bank_name ON scan_results(bank_name);
CREATE INDEX IF NOT EXISTS idx_session_id ON scan_results(scan_session_id);
CREATE INDEX IF NOT EXISTS idx_session_time ON scan_sessions(start_time);

-- Устанавливаем владельца таблиц
ALTER TABLE scan_results OWNER TO admin;
ALTER TABLE scan_sessions OWNER TO admin;

-- Проверяем создание
SELECT 'Database initialized successfully' as status;