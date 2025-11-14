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
        
        try {
            // Пробуем подключиться с super user credentials
            System.out.println("🔄 Attempting to connect with super user: " + SUPER_USER);
            superConn = DriverManager.getConnection(BASE_URL + "postgres", SUPER_USER, SUPER_PASSWORD);
            System.out.println("✅ Connected to PostgreSQL with super user");
            
        } catch (SQLException e1) {
            try {
                // Если не получилось, пробуем подключиться к template1 без пароля
                System.out.println("🔄 Trying template1 without password...");
                superConn = DriverManager.getConnection(BASE_URL + "template1", "postgres", "");
            } catch (SQLException e2) {
                try {
                    // Последняя попытка - подключиться без указания пользователя
                    System.out.println("🔄 Trying template1 with default settings...");
                    superConn = DriverManager.getConnection(BASE_URL + "template1");
                } catch (SQLException e3) {
                    System.err.println("❌ Cannot connect to PostgreSQL template1 database");
                    throw new SQLException("Failed to connect to PostgreSQL: " + e3.getMessage());
                }
            }
        }

        try (Statement stmt = superConn.createStatement()) {
            // Создаем пользователя если не существует
            try {
                stmt.execute("CREATE USER " + USER + " WITH PASSWORD '" + PASSWORD + "'");
                System.out.println("✅ User " + USER + " created successfully");
            } catch (SQLException e) {
                System.out.println("ℹ️ User " + USER + " already exists or cannot be created: " + e.getMessage());
            }

            // Создаем базу данных если не существует
            try {
                stmt.execute("CREATE DATABASE " + DATABASE_NAME + " OWNER " + USER);
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

        // Небольшая задержка чтобы убедиться что БД создана
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Теперь подключаемся к новой базе данных
        try {
            connection = DriverManager.getConnection(URL, USER, PASSWORD);
            System.out.println("✅ Successfully connected to newly created database");
        } catch (SQLException e) {
            System.err.println("❌ Failed to connect to new database: " + e.getMessage());
            throw e;
        }
    }

    private void createTables() throws SQLException {
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """;

        String createIndexes = """
            CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_results(scan_date);
            CREATE INDEX IF NOT EXISTS idx_severity ON scan_results(severity);
            CREATE INDEX IF NOT EXISTS idx_category ON scan_results(category);
            CREATE INDEX IF NOT EXISTS idx_bank_name ON scan_results(bank_name);
        """;

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createResultsTable);
            stmt.execute(createIndexes);
            System.out.println("✅ Database tables and indexes created successfully");
        }
    }

    public void saveVulnerability(String bankName, String title, String severity,
                                  String category, String statusCode, String proof,
                                  String recommendation, String scannerName) {
        String sql = """
            INSERT INTO scan_results 
            (bank_name, vulnerability_title, severity, category, status_code, proof, recommendation, scanner_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
                   status_code, proof, recommendation, scanner_name, scan_date
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

            // Сбрасываем последовательность ID
            stmt.execute("ALTER SEQUENCE scan_results_id_seq RESTART WITH 1");

            System.out.println("БД очищена");
        } catch (SQLException e) {
            System.err.println("Ошибка очистки: " + e.getMessage());
            throw new RuntimeException("Failed to clear database", e);
        }
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
