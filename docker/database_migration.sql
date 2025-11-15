-- Добавляем недостающие столбцы в существующую таблицу scan_results
ALTER TABLE scan_results
ADD COLUMN IF NOT EXISTS scan_session_id VARCHAR(100);

-- Создаем таблицу scan_sessions если она не существует
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

-- Создаем недостающие индексы
CREATE INDEX IF NOT EXISTS idx_session_id ON scan_results(scan_session_id);
CREATE INDEX IF NOT EXISTS idx_session_time ON scan_sessions(start_time);

-- Обновляем существующие записи, устанавливая значение по умолчанию для session_id
UPDATE scan_results SET scan_session_id = 'legacy_session' WHERE scan_session_id IS NULL;

-- Проверяем успешность миграции
SELECT 'Database migration completed successfully' as status;