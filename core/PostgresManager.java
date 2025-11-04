package core;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PostgresManager {
    private static final String URL = "jdbc:postgresql://localhost:5432/security_scanner";
    private static final String USER = "admin";
    private static final String PASSWORD = "admin";

    private Connection connection;

    public PostgresManager() {
        initializeDatabase();
    }

    private void initializeDatabase() {
        try {
            // Явная загрузка драйвера PostgreSQL
            Class.forName("org.postgresql.Driver");

            connection = DriverManager.getConnection(URL, USER, PASSWORD);
            createTables();
            System.out.println("✅ PostgreSQL database connected successfully");
        } catch (ClassNotFoundException e) {
            System.err.println("❌ PostgreSQL JDBC Driver not found. Add postgresql-42.7.3.jar to lib folder");
            e.printStackTrace();
        } catch (SQLException e) {
            System.err.println("❌ Database connection error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // остальной код без изменений...
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

        // Индексы для быстрого поиска
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

    // остальные методы без изменений...
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

        // Добавляем фильтры
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
                stats.put("total", rs.getInt("total"));
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
            stmt.execute("DELETE FROM scan_results");
            System.out.println("🗑️ All scan results cleared from database");
        } catch (SQLException e) {
            System.err.println("❌ Error clearing results: " + e.getMessage());
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