package core;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PostgresManager {
    // Используем переменные окружения или значения по умолчанию
    private static final String DB_HOST = System.getenv("DB_HOST") != null ? System.getenv("DB_HOST") : "localhost";
    private static final String DB_PORT = System.getenv("DB_PORT") != null ? System.getenv("DB_PORT") : "5432";
    private static final String BASE_URL = "jdbc:postgresql://" + DB_HOST + ":" + DB_PORT + "/";
    private static final String DATABASE_NAME = System.getenv("DB_NAME") != null ? System.getenv("DB_NAME") : "security_scanner";
    private static final String URL = BASE_URL + DATABASE_NAME;
    private static final String USER = System.getenv("DB_USER") != null ? System.getenv("DB_USER") : "admin";
    private static final String PASSWORD = System.getenv("DB_PASSWORD") != null ? System.getenv("DB_PASSWORD") : "admin";
    private static final String SUPER_USER = System.getenv("DB_SUPER_USER") != null ? System.getenv("DB_SUPER_USER") : "postgres";
    private static final String SUPER_PASSWORD = System.getenv("DB_SUPER_PASSWORD") != null ? System.getenv("DB_SUPER_PASSWORD") : "postgres";

    private Connection connection;

    public PostgresManager() {
        System.out.println("🔧 Database configuration:");
        System.out.println("  Host: " + DB_HOST + ":" + DB_PORT);
        System.out.println("  Database: " + DATABASE_NAME);
        System.out.println("  User: " + USER);
        System.out.println("  Super User: " + SUPER_USER);
        initializeDatabase();
    }

    private void initializeDatabase() {
        try {
            Class.forName("org.postgresql.Driver");

            // Пытаемся подключиться к целевой базе данных
            try {
                connection = DriverManager.getConnection(URL, USER, PASSWORD);
                System.out.println("✅ Connected to existing database: " + DATABASE_NAME);
            } catch (SQLException e) {
                // Если подключение не удалось, создаем базу и пользователя
                System.out.println("⚠️ Database connection failed, attempting to create database and user...");
                System.out.println("  Error: " + e.getMessage());
                createDatabaseAndUser();
            }

            createTables();
            System.out.println("✅ PostgreSQL database initialized successfully");

        } catch (ClassNotFoundException e) {
            System.err.println("❌ PostgreSQL JDBC Driver not found.");
            e.printStackTrace();
        } catch (SQLException e) {
            System.err.println("❌ Database connection error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void createDatabaseAndUser() throws SQLException {
        Connection superConn = null;

        System.out.println("🔧 Database creation configuration:");
        System.out.println("  Super User: " + SUPER_USER);
        System.out.println("  Target DB: " + DATABASE_NAME);
        System.out.println("  Base URL: " + BASE_URL);

        try {
            // ПЕРВАЯ ПОПЫТКА: подключиться к postgres с правильными учетными данными
            System.out.println("🔄 Attempt 1: Connecting to 'postgres' database with super user...");
            superConn = DriverManager.getConnection(BASE_URL + "postgres", SUPER_USER, SUPER_PASSWORD);
            System.out.println("✅ Connected to PostgreSQL with super user");

        } catch (SQLException e1) {
            System.err.println("❌ Attempt 1 failed: " + e1.getMessage());

            try {
                // ВТОРАЯ ПОПЫТКА: подключиться к template1 с теми же учетными данными
                System.out.println("🔄 Attempt 2: Connecting to 'template1' database with super user...");
                superConn = DriverManager.getConnection(BASE_URL + "template1", SUPER_USER, SUPER_PASSWORD);
                System.out.println("✅ Connected to template1 with super user");

            } catch (SQLException e2) {
                System.err.println("❌ Attempt 2 failed: " + e2.getMessage());

                // ТРЕТЬЯ ПОПЫТКА: попробовать с пользователем postgres и паролем postgres (часто используется по умолчанию)
                try {
                    System.out.println("🔄 Attempt 3: Trying default 'postgres/postgres' credentials...");
                    superConn = DriverManager.getConnection(BASE_URL + "postgres", "postgres", "postgres");
                    System.out.println("✅ Connected with default credentials");

                } catch (SQLException e3) {
                    System.err.println("❌ All connection attempts failed:");
                    System.err.println("   - " + e1.getMessage());
                    System.err.println("   - " + e2.getMessage());
                    System.err.println("   - " + e3.getMessage());
                    throw new SQLException("Cannot connect to PostgreSQL. Check your credentials and make sure PostgreSQL is running.");
                }
            }
        }

        // Если мы здесь - подключение установлено
        try (Statement stmt = superConn.createStatement()) {
            // Создаем пользователя если не существует
            try {
                String createUserSql = "CREATE USER " + USER + " WITH PASSWORD '" + PASSWORD + "'";
                stmt.execute(createUserSql);
                System.out.println("✅ User " + USER + " created successfully");
            } catch (SQLException e) {
                System.out.println("ℹ️ User " + USER + " already exists or cannot be created: " + e.getMessage());
            }

            // Создаем базу данных если не существует
            try {
                String createDbSql = "CREATE DATABASE " + DATABASE_NAME + " WITH OWNER " + USER +
                        " ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8'";
                stmt.execute(createDbSql);
                System.out.println("✅ Database " + DATABASE_NAME + " created successfully");
            } catch (SQLException e) {
                System.out.println("ℹ️ Database " + DATABASE_NAME + " already exists or cannot be created: " + e.getMessage());
            }

            // Даем права пользователю на базу данных
            try {
                stmt.execute("GRANT ALL PRIVILEGES ON DATABASE " + DATABASE_NAME + " TO " + USER);
                System.out.println("✅ Privileges granted to user " + USER);
            } catch (SQLException e) {
                System.out.println("⚠️ Could not grant privileges: " + e.getMessage());
            }

        } finally {
            if (superConn != null && !superConn.isClosed()) {
                superConn.close();
            }
        }

        // Задержка чтобы БД гарантированно создалась
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Подключаемся к новой базе данных
        try {
            connection = DriverManager.getConnection(URL, USER, PASSWORD);
            System.out.println("✅ Successfully connected to database: " + DATABASE_NAME);
        } catch (SQLException e) {
            System.err.println("❌ Failed to connect to new database: " + e.getMessage());
            throw e;
        }
    }
    private void createTables() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            // Пытаемся создать таблицы
            String createResultsTable = """
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
            )
        """;

            String createSessionsTable = """
            CREATE TABLE IF NOT EXISTS scan_sessions (
                session_id VARCHAR(100) PRIMARY KEY,
                session_name VARCHAR(500) NOT NULL,
                banks_count INTEGER DEFAULT 0,
                vulnerabilities_count INTEGER DEFAULT 0,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                status VARCHAR(20) DEFAULT 'COMPLETED',
                config_json TEXT
            )
        """;

            stmt.execute(createResultsTable);
            stmt.execute(createSessionsTable);
            System.out.println("✅ Database tables created successfully");

        } catch (SQLException e) {
            System.err.println("❌ Error creating tables: " + e.getMessage());

            // Если ошибка связана с правами доступа, попробуем создать таблицы с минимальными привилегиями
            if (e.getMessage().contains("нет доступа") || e.getMessage().contains("permission denied")) {
                System.out.println("🔄 Trying to create tables with alternative approach...");
                createTablesWithMinimalPrivileges();
            } else {
                throw e;
            }
        }

        // Создаем индексы
        createIndexes();

        // Выполняем миграцию
        performMigration();
    }

    private void createTablesWithMinimalPrivileges() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            // Проверяем существование таблиц и создаем только если их нет
            ResultSet rs = stmt.executeQuery(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('scan_results', 'scan_sessions')"
            );
            rs.next();
            int tableCount = rs.getInt(1);

            if (tableCount == 0) {
                System.out.println("⚠️ No tables found. Application will run without database storage.");
                System.out.println("💡 Please create tables manually or grant CREATE privileges to user 'admin'");
            } else {
                System.out.println("✅ Tables already exist: " + tableCount + " tables found");
            }
        }
    }

    private void createIndexes() {
        String[] indexes = {
                "CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_results(scan_date)",
                "CREATE INDEX IF NOT EXISTS idx_severity ON scan_results(severity)",
                "CREATE INDEX IF NOT EXISTS idx_category ON scan_results(category)",
                "CREATE INDEX IF NOT EXISTS idx_bank_name ON scan_results(bank_name)",
                "CREATE INDEX IF NOT EXISTS idx_session_id ON scan_results(scan_session_id)",
                "CREATE INDEX IF NOT EXISTS idx_session_time ON scan_sessions(start_time)"
        };

        try (Statement stmt = connection.createStatement()) {
            for (String index : indexes) {
                try {
                    stmt.execute(index);
                } catch (SQLException e) {
                    System.out.println("⚠️ Could not create index: " + e.getMessage());
                }
            }
            System.out.println("✅ Database indexes created/verified");
        } catch (SQLException e) {
            System.err.println("❌ Error creating indexes: " + e.getMessage());
        }
    }

    private void performMigration() {
        try (Statement stmt = connection.createStatement()) {
            // Добавляем столбец scan_session_id если его нет
            try {
                stmt.execute("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS scan_session_id VARCHAR(100)");
                System.out.println("✅ Database migration: scan_session_id column verified");

                // Обновляем существующие записи
                int updatedRows = stmt.executeUpdate("UPDATE scan_results SET scan_session_id = 'legacy_session' WHERE scan_session_id IS NULL");
                if (updatedRows > 0) {
                    System.out.println("✅ Updated " + updatedRows + " records with session_id");
                }
            } catch (SQLException e) {
                System.out.println("ℹ️ Migration already completed: " + e.getMessage());
            }
        } catch (SQLException e) {
            System.err.println("❌ Error during migration: " + e.getMessage());
        }
    }
    // Старый метод для обратной совместимости
    public void saveVulnerability(String bankName, String title, String severity,
                                  String category, String statusCode, String proof,
                                  String recommendation, String scannerName) {
        saveVulnerability(bankName, title, severity, category, statusCode, proof, recommendation, scannerName, "default_session");
    }

    // Новый метод с поддержкой сессий
    public void saveVulnerability(String bankName, String title, String severity,
                                  String category, String statusCode, String proof,
                                  String recommendation, String scannerName, String scanSessionId) {
        String sql = """
            INSERT INTO scan_results 
            (bank_name, vulnerability_title, severity, category, status_code, proof, recommendation, scanner_name, scan_session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, bankName);
            pstmt.setString(2, title);
            pstmt.setString(3, severity);
            pstmt.setString(4, category);
            pstmt.setString(5, statusCode);
            pstmt.setString(6, proof);
            pstmt.setString(7, recommendation);
            pstmt.setString(8, scannerName);
            pstmt.setString(9, scanSessionId);
            pstmt.executeUpdate();

            System.out.println("💾 Saved to PostgreSQL: " + title + " [" + severity + "]");
        } catch (SQLException e) {
            System.err.println("❌ Error saving vulnerability: " + e.getMessage());
        }
    }

    public List<Map<String, Object>> getScanResults(String severityFilter, String categoryFilter, String bankFilter) {
        List<Map<String, Object>> results = new ArrayList<>();

        StringBuilder sql = new StringBuilder("""
            SELECT id, bank_name, vulnerability_title, severity, category, 
                   status_code, proof, recommendation, scanner_name, scan_date, scan_session_id
            FROM scan_results 
            WHERE 1=1
        """);

        if (severityFilter != null && !severityFilter.isEmpty()) {
            sql.append(" AND severity = ?");
        }
        if (categoryFilter != null && !categoryFilter.isEmpty()) {
            sql.append(" AND category = ?");
        }
        if (bankFilter != null && !bankFilter.isEmpty()) {
            sql.append(" AND bank_name = ?");
        }

        sql.append(" ORDER BY scan_date DESC");

        try (PreparedStatement pstmt = connection.prepareStatement(sql.toString())) {
            int paramIndex = 1;
            if (severityFilter != null && !severityFilter.isEmpty()) {
                pstmt.setString(paramIndex++, severityFilter);
            }
            if (categoryFilter != null && !categoryFilter.isEmpty()) {
                pstmt.setString(paramIndex++, categoryFilter);
            }
            if (bankFilter != null && !bankFilter.isEmpty()) {
                pstmt.setString(paramIndex, bankFilter);
            }

            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {
                Map<String, Object> result = new HashMap<>();
                result.put("id", rs.getInt("id"));
                result.put("bankName", rs.getString("bank_name"));
                result.put("vulnerabilityTitle", rs.getString("vulnerability_title"));
                result.put("severity", rs.getString("severity"));
                result.put("category", rs.getString("category"));
                result.put("statusCode", rs.getString("status_code"));
                result.put("proof", rs.getString("proof"));
                result.put("recommendation", rs.getString("recommendation"));
                result.put("scannerName", rs.getString("scanner_name"));
                result.put("scanDate", rs.getTimestamp("scan_date").toString());
                result.put("scanSessionId", rs.getString("scan_session_id"));
                results.add(result);
            }
        } catch (SQLException e) {
            System.err.println("❌ Error reading scan results: " + e.getMessage());
        }

        return results;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();

        try {
            // Total count
            String totalSql = "SELECT COUNT(*) as total FROM scan_results";
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(totalSql)) {
                if (rs.next()) {
                    stats.put("total", rs.getInt("total"));
                }
            }

            // Count by severity
            String severitySql = "SELECT severity, COUNT(*) as count FROM scan_results GROUP BY severity";
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(severitySql)) {

                int critical = 0, high = 0, medium = 0, low = 0;
                while (rs.next()) {
                    String severity = rs.getString("severity");
                    int count = rs.getInt("count");
                    switch (severity) {
                        case "CRITICAL": critical = count; break;
                        case "HIGH": high = count; break;
                        case "MEDIUM": medium = count; break;
                        case "LOW": low = count; break;
                    }
                }
                stats.put("critical", critical);
                stats.put("high", high);
                stats.put("medium", medium);
                stats.put("low", low);
            }

            // Count by category
            String categorySql = "SELECT category, COUNT(*) as count FROM scan_results GROUP BY category";
            Map<String, Integer> byCategory = new HashMap<>();
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(categorySql)) {
                while (rs.next()) {
                    byCategory.put(rs.getString("category"), rs.getInt("count"));
                }
            }
            stats.put("byCategory", byCategory);

            // Count by bank
            String bankSql = "SELECT bank_name, COUNT(*) as count FROM scan_results GROUP BY bank_name";
            Map<String, Integer> byBank = new HashMap<>();
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(bankSql)) {
                while (rs.next()) {
                    byBank.put(rs.getString("bank_name"), rs.getInt("count"));
                }
            }
            stats.put("byBank", byBank);

        } catch (SQLException e) {
            System.err.println("❌ Error calculating stats: " + e.getMessage());
        }

        return stats;
    }

    public void clearResults() {
        try (Statement stmt = connection.createStatement()) {
            // Отключаем проверку внешних ключей для безопасной очистки
            stmt.execute("TRUNCATE TABLE scan_results RESTART IDENTITY CASCADE");
            stmt.execute("TRUNCATE TABLE scan_sessions RESTART IDENTITY CASCADE");

            // Сбрасываем последовательность ID
            stmt.execute("ALTER SEQUENCE scan_results_id_seq RESTART WITH 1");

            System.out.println("🗑️ База данных полностью очищена (результаты и сессии)");
        } catch (SQLException e) {
            System.err.println("❌ Ошибка очистки базы данных: " + e.getMessage());
            throw new RuntimeException("Failed to clear database", e);
        }
    }

    // Методы для работы с сессиями сканирования

    /**
     * Создает новую сессию сканирования
     */
    public String createSession(String sessionName, String configJson) {
        String sessionId = generateSessionId();

        String sql = """
            INSERT INTO scan_sessions 
            (session_id, session_name, start_time, config_json, status)
            VALUES (?, ?, CURRENT_TIMESTAMP, ?, 'RUNNING')
        """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, sessionId);
            pstmt.setString(2, sessionName);
            pstmt.setString(3, configJson);
            pstmt.executeUpdate();

            System.out.println("✅ Создана сессия сканирования: " + sessionId);
            return sessionId;
        } catch (SQLException e) {
            System.err.println("❌ Ошибка создания сессии: " + e.getMessage());
            return null;
        }
    }

    /**
     * Завершает сессию и сохраняет статистику
     */
    public void completeSession(String sessionId, int banksCount, int vulnerabilitiesCount) {
        String sql = """
            UPDATE scan_sessions 
            SET end_time = CURRENT_TIMESTAMP, 
                status = 'COMPLETED',
                banks_count = ?,
                vulnerabilities_count = ?
            WHERE session_id = ?
        """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, banksCount);
            pstmt.setInt(2, vulnerabilitiesCount);
            pstmt.setString(3, sessionId);
            pstmt.executeUpdate();

            System.out.println("✅ Сессия завершена: " + sessionId);
        } catch (SQLException e) {
            System.err.println("❌ Ошибка завершения сессии: " + e.getMessage());
        }
    }

    /**
     * Получает список всех сессий
     */
    public List<Map<String, Object>> getAllSessions() {
        List<Map<String, Object>> sessions = new ArrayList<>();
        String sql = """
            SELECT session_id, session_name, banks_count, vulnerabilities_count, 
                   start_time, end_time, status
            FROM scan_sessions 
            ORDER BY start_time DESC
        """;

        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                Map<String, Object> session = new HashMap<>();
                session.put("sessionId", rs.getString("session_id"));
                session.put("sessionName", rs.getString("session_name"));
                session.put("banksCount", rs.getInt("banks_count"));
                session.put("vulnerabilitiesCount", rs.getInt("vulnerabilities_count"));
                session.put("startTime", rs.getTimestamp("start_time").toString());
                session.put("endTime", rs.getTimestamp("end_time") != null ?
                        rs.getTimestamp("end_time").toString() : null);
                session.put("status", rs.getString("status"));
                sessions.add(session);
            }
        } catch (SQLException e) {
            System.err.println("❌ Ошибка получения сессий: " + e.getMessage());
        }

        return sessions;
    }

    /**
     * Сравнивает две сессии сканирования
     */
    public Map<String, Object> compareSessions(String sessionId1, String sessionId2) {
        Map<String, Object> comparison = new HashMap<>();

        // Получаем статистику по уязвимостям для обеих сессий
        String sql = """
            SELECT severity, COUNT(*) as count, scan_session_id
            FROM scan_results 
            WHERE scan_session_id IN (?, ?)
            GROUP BY severity, scan_session_id
            ORDER BY severity
        """;

        Map<String, Map<String, Integer>> severityStats = new HashMap<>();
        severityStats.put(sessionId1, new HashMap<>());
        severityStats.put(sessionId2, new HashMap<>());

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, sessionId1);
            pstmt.setString(2, sessionId2);

            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                String sessionId = rs.getString("scan_session_id");
                String severity = rs.getString("severity");
                int count = rs.getInt("count");
                severityStats.get(sessionId).put(severity, count);
            }
        } catch (SQLException e) {
            System.err.println("❌ Ошибка сравнения сессий: " + e.getMessage());
        }

        // Анализ новых/исправленных уязвимостей
        List<Map<String, Object>> newVulnerabilities = findNewVulnerabilities(sessionId1, sessionId2);
        List<Map<String, Object>> fixedVulnerabilities = findFixedVulnerabilities(sessionId1, sessionId2);

        comparison.put("session1Stats", severityStats.get(sessionId1));
        comparison.put("session2Stats", severityStats.get(sessionId2));
        comparison.put("newVulnerabilities", newVulnerabilities);
        comparison.put("fixedVulnerabilities", fixedVulnerabilities);
        comparison.put("newCount", newVulnerabilities.size());
        comparison.put("fixedCount", fixedVulnerabilities.size());

        return comparison;
    }

    private List<Map<String, Object>> findNewVulnerabilities(String oldSessionId, String newSessionId) {
        // Находим уязвимости, которые есть в новой сессии, но нет в старой
        String sql = """
            SELECT r2.* 
            FROM scan_results r2 
            WHERE r2.scan_session_id = ?
            AND NOT EXISTS (
                SELECT 1 FROM scan_results r1 
                WHERE r1.scan_session_id = ? 
                AND r1.vulnerability_title = r2.vulnerability_title 
                AND r1.bank_name = r2.bank_name
                AND r1.severity = r2.severity
            )
        """;

        return executeVulnerabilityQuery(sql, newSessionId, oldSessionId);
    }

    private List<Map<String, Object>> findFixedVulnerabilities(String oldSessionId, String newSessionId) {
        // Находим уязвимости, которые были в старой сессии, но исправлены в новой
        String sql = """
            SELECT r1.* 
            FROM scan_results r1 
            WHERE r1.scan_session_id = ?
            AND NOT EXISTS (
                SELECT 1 FROM scan_results r2 
                WHERE r2.scan_session_id = ? 
                AND r2.vulnerability_title = r1.vulnerability_title 
                AND r2.bank_name = r1.bank_name
                AND r2.severity = r1.severity
            )
        """;

        return executeVulnerabilityQuery(sql, oldSessionId, newSessionId);
    }

    private List<Map<String, Object>> executeVulnerabilityQuery(String sql, String sessionId1, String sessionId2) {
        List<Map<String, Object>> vulnerabilities = new ArrayList<>();

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, sessionId1);
            pstmt.setString(2, sessionId2);

            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                Map<String, Object> vuln = new HashMap<>();
                vuln.put("id", rs.getInt("id"));
                vuln.put("bankName", rs.getString("bank_name"));
                vuln.put("vulnerabilityTitle", rs.getString("vulnerability_title"));
                vuln.put("severity", rs.getString("severity"));
                vuln.put("category", rs.getString("category"));
                vuln.put("scannerName", rs.getString("scanner_name"));
                vuln.put("scanDate", rs.getTimestamp("scan_date").toString());
                vulnerabilities.add(vuln);
            }
        } catch (SQLException e) {
            System.err.println("❌ Ошибка выполнения запроса уязвимостей: " + e.getMessage());
        }

        return vulnerabilities;
    }

    private String generateSessionId() {
        return "scan_" + System.currentTimeMillis() + "_" + java.util.UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * Получает результаты для конкретной сессии
     */
    public List<Map<String, Object>> getResultsBySession(String sessionId) {
        List<Map<String, Object>> results = new ArrayList<>();

        String sql = """
            SELECT id, bank_name, vulnerability_title, severity, category, 
                   status_code, proof, recommendation, scanner_name, scan_date
            FROM scan_results 
            WHERE scan_session_id = ?
            ORDER BY scan_date DESC
        """;

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, sessionId);
            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {
                Map<String, Object> result = new HashMap<>();
                result.put("id", rs.getInt("id"));
                result.put("bankName", rs.getString("bank_name"));
                result.put("vulnerabilityTitle", rs.getString("vulnerability_title"));
                result.put("severity", rs.getString("severity"));
                result.put("category", rs.getString("category"));
                result.put("statusCode", rs.getString("status_code"));
                result.put("proof", rs.getString("proof"));
                result.put("recommendation", rs.getString("recommendation"));
                result.put("scannerName", rs.getString("scanner_name"));
                result.put("scanDate", rs.getTimestamp("scan_date").toString());
                results.add(result);
            }
        } catch (SQLException e) {
            System.err.println("❌ Error reading session results: " + e.getMessage());
        }

        return results;
    }

    public Connection getConnection() {
        return connection;
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                System.out.println("✅ Database connection closed");
            }
        } catch (SQLException e) {
            System.err.println("❌ Error closing database: " + e.getMessage());
        }
    }
}