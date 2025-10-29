import scanners.owasp.AuthManager;

public class TestAuth {
    public static void main(String[] args) {
        System.out.println("🧪 Тестирование аутентификации с банком...");
        
        // Тестируем аутентификацию
        AuthManager.testAuthentication();
    }
}
