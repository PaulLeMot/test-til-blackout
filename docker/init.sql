-- Создаем пользователя admin если не существует
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'admin') THEN
        CREATE USER admin WITH PASSWORD 'admin';
        RAISE NOTICE 'User admin created';
    ELSE
        RAISE NOTICE 'User admin already exists';
    END IF;
END
$$;

-- Создаем базу данных security_scanner если не существует
SELECT 'CREATE DATABASE security_scanner OWNER admin'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'security_scanner');

-- Подключаемся к созданной базе данных
\c security_scanner;

-- Даем все права пользователю admin на базу данных
GRANT ALL PRIVILEGES ON DATABASE security_scanner TO admin;

-- Создаем таблицу scan_results
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Создаем индексы
CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_results(scan_date);
CREATE INDEX IF NOT EXISTS idx_severity ON scan_results(severity);
CREATE INDEX IF NOT EXISTS idx_category ON scan_results(category);
CREATE INDEX IF NOT EXISTS idx_bank_name ON scan_results(bank_name);

-- Даем права на таблицы пользователю admin
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO admin;

-- Устанавливаем владельца таблицы
ALTER TABLE scan_results OWNER TO admin;

-- Проверяем создание
SELECT 'Database initialized successfully' as status;