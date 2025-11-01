import java.io.*;
import java.net.*;
import java.net.http.*;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.*;
import java.util.concurrent.*;
import com.fasterxml.jackson.databind.*;
import java.time.Duration;

public class AccountCloser {
    private static final ObjectMapper mapper = new ObjectMapper();
    private final String baseUrl;
    private final String password;
    private final HttpClient client;
    
    public AccountCloser(String baseUrl, String password) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.password = password;
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }
    
    public String getAccessToken(String username) {
        try {
            String loginUrl = baseUrl + "/auth/login";
            Map<String, String> payload = Map.of(
                "username", username,
                "password", password
            );
            
            String requestBody = mapper.writeValueAsString(payload);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(loginUrl))
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .timeout(Duration.ofSeconds(10))
                    .build();
            
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode data = mapper.readTree(response.body());
                String token = data.get("access_token").asText();
                if (token != null && !token.isEmpty()) {
                    System.out.println("✅ Токен получен для " + username);
                    return token;
                }
            } else {
                System.out.println("❌ Ошибка аутентификации " + username + ": " + response.statusCode());
            }
        } catch (Exception e) {
            System.out.println("❌ Ошибка при получении токена для " + username + ": " + e.getMessage());
        }
        return null;
    }
    
    public List<Map<String, Object>> getUserAccounts(String token) {
        try {
            String accountsUrl = baseUrl + "/accounts";
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(accountsUrl))
                    .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + token)
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .build();
            
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode data = mapper.readTree(response.body());
                JsonNode accountsNode = data.path("data").path("account");
                List<Map<String, Object>> accounts = new ArrayList<>();
                
                if (accountsNode.isArray()) {
                    for (JsonNode accountNode : accountsNode) {
                        Map<String, Object> account = new HashMap<>();
                        account.put("accountId", accountNode.path("accountId").asText());
                        account.put("nickname", accountNode.path("nickname").asText("N/A"));
                        account.put("status", accountNode.path("status").asText("N/A"));
                        accounts.add(account);
                    }
                }
                System.out.println("📊 Найдено счетов: " + accounts.size());
                return accounts;
            } else if (response.statusCode() == 429) {
                System.out.println("⏳ Получен 429, ждем 10 секунд...");
                Thread.sleep(10000);
                return getUserAccounts(token);
            } else {
                System.out.println("❌ Ошибка получения счетов: " + response.statusCode());
            }
        } catch (Exception e) {
            System.out.println("❌ Ошибка при получении счетов: " + e.getMessage());
        }
        return Collections.emptyList();
    }
    
    public boolean closeAccountStatus(String token, String accountId) {
        try {
            String statusUrl = baseUrl + "/accounts/" + accountId + "/status";
            Map<String, String> payload = Map.of("status", "closed");
            String requestBody = mapper.writeValueAsString(payload);
            
            System.out.println("🔒 Закрываем счет через статус: " + accountId);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(statusUrl))
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + token)
                    .PUT(HttpRequest.BodyPublishers.ofString(requestBody))
                    .timeout(Duration.ofSeconds(10))
                    .build();
            
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            System.out.println("📥 Ответ: HTTP " + response.statusCode());
            
            if (response.statusCode() == 200) {
                System.out.println("✅ Счет " + accountId + " закрыт через изменение статуса");
                return true;
            } else if (response.statusCode() == 429) {
                System.out.println("⏳ Получен 429, ждем 10 секунд...");
                Thread.sleep(10000);
                return closeAccountStatus(token, accountId);
            } else {
                System.out.println("❌ Ошибка закрытия счета " + accountId + ": " + response.statusCode());
                if (!response.body().isEmpty()) {
                    System.out.println("📄 Ответ: " + response.body());
                }
                return false;
            }
        } catch (Exception e) {
            System.out.println("❌ Ошибка при закрытии счета " + accountId + ": " + e.getMessage());
            return false;
        }
    }
    
    public boolean closeAccountWithBalance(String token, String accountId) {
        try {
            String closeUrl = baseUrl + "/accounts/" + accountId + "/close";
            Map<String, String> payload = Map.of("action", "donate");
            String requestBody = mapper.writeValueAsString(payload);
            
            System.out.println("🎁 Закрываем счет с переводом остатка: " + accountId);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(closeUrl))
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + token)
                    .PUT(HttpRequest.BodyPublishers.ofString(requestBody))
                    .timeout(Duration.ofSeconds(10))
                    .build();
            
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            System.out.println("📥 Ответ: HTTP " + response.statusCode());
            
            if (response.statusCode() == 200) {
                System.out.println("✅ Счет " + accountId + " закрыт с переводом остатка банку");
                return true;
            } else if (response.statusCode() == 429) {
                System.out.println("⏳ Получен 429, ждем 10 секунд...");
                Thread.sleep(10000);
                return closeAccountWithBalance(token, accountId);
            } else {
                System.out.println("❌ Ошибка закрытия счета " + accountId + ": " + response.statusCode());
                if (!response.body().isEmpty()) {
                    System.out.println("📄 Ответ: " + response.body());
                }
                return false;
            }
        } catch (Exception e) {
            System.out.println("❌ Ошибка при закрытии счета " + accountId + ": " + e.getMessage());
            return false;
        }
    }
    
    public int cleanupUserAccounts(String username) {
        System.out.println("\n🔍 Очистка счетов пользователя: " + username);
        System.out.println("=".repeat(50));
        
        String token = getAccessToken(username);
        if (token == null) {
            System.out.println("❌ Не удалось получить токен для " + username);
            return 0;
        }
        
        List<Map<String, Object>> accounts = getUserAccounts(token);
        if (accounts.isEmpty()) {
            System.out.println("ℹ️ У пользователя " + username + " нет счетов для удаления");
            return 0;
        }
        
        System.out.println("🎯 Начинаем закрытие " + accounts.size() + " счетов...");
        
        int closedCount = 0;
        for (int i = 0; i < accounts.size(); i++) {
            Map<String, Object> account = accounts.get(i);
            String accountId = (String) account.get("accountId");
            
            if (accountId == null || accountId.isEmpty()) {
                continue;
            }
            
            System.out.println("\n[" + (i + 1) + "/" + accounts.size() + "] Закрытие счета: " + accountId);
            System.out.println("📝 Информация: " + account.get("nickname") + " - " + account.get("status"));
            
            if (closeAccountStatus(token, accountId)) {
                closedCount++;
            } else {
                System.out.println("🔄 Пробуем закрыть с переводом остатка...");
                if (closeAccountWithBalance(token, accountId)) {
                    closedCount++;
                }
            }
            
            if (i < accounts.size() - 1) {
                int waitTime = 2000;
                System.out.println("⏳ Ждем " + (waitTime / 1000) + " секунды перед следующим счетом...");
                try {
                    Thread.sleep(waitTime);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        
        System.out.println("\n✅ Пользователь " + username + ": закрыто " + closedCount + " из " + accounts.size() + " счетов");
        return closedCount;
    }
    
    public static void cleanupAllBanks() {
        List<String> banks = Arrays.asList(
            "https://sbank.open.bankingapi.ru",
            "https://abank.open.bankingapi.ru", 
            "https://vbank.open.bankingapi.ru"
        );
        
        String password = "***REMOVED***";
        List<String> users = new ArrayList<>();
        for (int i = 1; i <= 10; i++) {
            users.add("team172-" + i);
        }
        
        System.out.println("🔒 СКРИПТ ПОЛНОЙ ОЧИСТКИ СЧЕТОВ");
        System.out.println("📍 Банки: sbank, abank, vbank");
        System.out.println("👥 Пользователи: " + String.join(", ", users));
        System.out.println("📋 Методы: PUT /accounts/{id}/status и PUT /accounts/{id}/close");
        
        System.out.print("\n❓ Вы уверены, что хотите закрыть ВСЕ счета во ВСЕХ банках? (y/N): ");
        Scanner scanner = new Scanner(System.in);
        String confirm = scanner.nextLine();
        scanner.close();
        
        if (!confirm.equalsIgnoreCase("y")) {
            System.out.println("❌ Операция отменена");
            return;
        }
        
        int totalClosed = 0;
        int totalUsers = 0;
        
        for (String bankUrl : banks) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("🏦 НАЧИНАЕМ ОЧИСТКУ БАНКА: " + bankUrl);
            System.out.println("=".repeat(60));
            
            AccountCloser closer = new AccountCloser(bankUrl, password);
            int bankClosed = 0;
            
            for (String user : users) {
                try {
                    int userClosed = closer.cleanupUserAccounts(user);
                    bankClosed += userClosed;
                    totalUsers++;
                    
                    if (!user.equals(users.get(users.size() - 1))) {
                        int waitTime = 3000;
                        System.out.println("⏳ Ждем " + (waitTime / 1000) + " секунды перед следующим пользователем...");
                        Thread.sleep(waitTime);
                    }
                } catch (Exception e) {
                    System.out.println("\n💥 Ошибка при очистке пользователя " + user + ": " + e.getMessage());
                }
            }
            
            totalClosed += bankClosed;
            System.out.println("\n🏦 ИТОГ по банку " + bankUrl + ": закрыто " + bankClosed + " счетов");
            
            if (!bankUrl.equals(banks.get(banks.size() - 1))) {
                int waitTime = 5000;
                System.out.println("⏳ Ждем " + (waitTime / 1000) + " секунд перед следующим банком...");
                try {
                    Thread.sleep(waitTime);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        
        System.out.println("\n" + "🎉".repeat(20));
        System.out.println("ПОЛНАЯ ОЧИСТКА ЗАВЕРШЕНА!");
        System.out.println("🏦 Обработано банков: " + banks.size());
        System.out.println("👥 Обработано пользователей: " + totalUsers);
        System.out.println("📊 Всего закрыто счетов: " + totalClosed);
        System.out.println("🎉".repeat(20));
    }
    
    public static void main(String[] args) {
        try {
            cleanupAllBanks();
        } catch (Exception e) {
            System.out.println("\n💥 Критическая ошибка в основном потоке: " + e.getMessage());
        }
    }
}
