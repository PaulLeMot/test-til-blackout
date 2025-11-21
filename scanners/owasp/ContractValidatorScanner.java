package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.TestedEndpoint;
import core.ContractValidator;
import java.util.*;

public class ContractValidatorScanner implements SecurityScanner {

    @Override
    public String getName() {
        return "Contract Validator Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        return scanEndpoints(null, config, apiClient);
    }

    @Override
    public List<Vulnerability> scanEndpoints(List<TestedEndpoint> endpoints, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            System.out.println("(ContractValidator) Запуск валидации контрактов...");

            // Получаем учетные данные из конфигурации
            String clientId = config.getClientId();
            String clientSecret = config.getClientSecret();

            if (clientId == null || clientSecret == null) {
                System.err.println("(ContractValidator) Не указаны clientId и clientSecret");
                return vulnerabilities;
            }

            System.out.println("(ContractValidator) Используем clientId: " + clientId);

            // Создаем ContractValidator с учетными данными из конфига
            ContractValidator validator = new ContractValidator(clientId, clientSecret);

            // Устанавливаем baseUrl если доступен (для комбинированного режима)
            if (config.getTargetBaseUrl() != null && !config.getTargetBaseUrl().isEmpty()) {
                validator.setBaseUrl(config.getTargetBaseUrl());
                System.out.println("(ContractValidator) Установлен baseUrl: " + config.getTargetBaseUrl());
            }

            // Запускаем валидацию
            List<ContractValidator.ValidationResult> results = validator.validateAllContracts();

            // Преобразуем результаты в Vulnerability (исключая INFO уровень)
            for (ContractValidator.ValidationResult result : results) {
                Vulnerability vuln = convertToVulnerability(result);
                if (vuln != null && vuln.getSeverity() != Vulnerability.Severity.INFO) {
                    vulnerabilities.add(vuln);
                }
            }

            System.out.println("(ContractValidator) Валидация завершена. Найдено уязвимостей: " + vulnerabilities.size());

        } catch (Exception e) {
            System.err.println("(ContractValidator) Ошибка при валидации контрактов: " + e.getMessage());
            e.printStackTrace();
        }

        return vulnerabilities;
    }

    private Vulnerability convertToVulnerability(ContractValidator.ValidationResult result) {
        Vulnerability vuln = new Vulnerability();

        // Определяем уровень критичности на основе статуса кода
        Vulnerability.Severity severity = determineSeverity(result.statusCode, result.status);

        vuln.setTitle("Contract Validation: " + result.specName);
        vuln.setDescription(
                "Проверка соответствия API контракту для спецификации: " + result.specName + "\n\n" +
                        "Эндпоинт: " + result.method + " " + result.endpoint + "\n" +
                        "Статус: " + result.message + "\n" +
                        "Код ответа: " + result.statusCode + "\n" +
                        "Время ответа: " + result.responseTime + "ms"
        );

        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.CONTRACT_VALIDATION);
        vuln.setEndpoint(result.endpoint);
        vuln.setMethod(result.method);
        vuln.setStatusCode(result.statusCode);

        // Формируем доказательство
        String evidence = "Результат валидации контракта:\n" +
                "Спецификация: " + result.specName + "\n" +
                "Эндпоинт: " + result.method + " " + result.endpoint + "\n" +
                "Статус код: " + result.statusCode + "\n" +
                "Сообщение: " + result.message + "\n" +
                "Время ответа: " + result.responseTime + "ms";

        if (result.responseBody != null && !result.responseBody.isEmpty()) {
            evidence += "\nТело ответа (первые 500 символов): " +
                    result.responseBody.substring(0, Math.min(500, result.responseBody.length()));
        }

        vuln.setEvidence(evidence);

        vuln.setRecommendations(Arrays.asList(
                "Убедитесь, что API соответствует OpenAPI спецификации",
                "Проверьте корректность всех обязательных полей в ответах",
                "Убедитесь, что все задекларированные эндпоинты доступны и работают корректно",
                "Проверьте соответствие форматов данных (JSON Schema)",
                "Убедитесь в корректности HTTP статус кодов",
                "Проверьте валидацию входных параметров и тел запросов"
        ));

        return vuln;
    }

    private Vulnerability.Severity determineSeverity(int statusCode, ContractValidator.ValidationStatus status) {
        // Определяем уровень критичности на основе статуса ответа
        // ИСКЛЮЧАЕМ INFO уровень, так как он не поддерживается в БД
        if (statusCode >= 500) {
            return Vulnerability.Severity.HIGH; // Ошибки сервера
        } else if (statusCode >= 400 && statusCode != 404) {
            return Vulnerability.Severity.MEDIUM; // Клиентские ошибки (кроме 404)
        } else if (statusCode == 404) {
            return Vulnerability.Severity.LOW; // Не найден - низкий приоритет
        } else if (statusCode >= 200 && statusCode < 300) {
            return Vulnerability.Severity.LOW; // Успешные ответы теперь LOW вместо INFO
        } else {
            return Vulnerability.Severity.LOW; // Другое теперь LOW вместо INFO
        }
    }
}