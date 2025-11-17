package core;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.logging.Logger;

public class ConfigParser {
    private static final Logger logger = Logger.getLogger(ConfigParser.class.getName());

    public static ScanConfig parseConfig(String jsonConfig) {
        ScanConfig config = new ScanConfig();

        try {
            JSONObject jsonObject = new JSONObject(jsonConfig);
            logger.info("[CONFIG_PARSER] Исходный JSON: " + jsonConfig);

            // Парсинг банков
            if (jsonObject.has("banks")) {
                JSONArray banksArray = jsonObject.getJSONArray("banks");
                logger.info("[CONFIG_PARSER] Found " + banksArray.length() + " bank objects");

                for (int i = 0; i < banksArray.length(); i++) {
                    JSONObject bankObj = banksArray.getJSONObject(i);
                    String baseUrl = bankObj.getString("baseUrl");
                    String specUrl = bankObj.getString("specUrl");

                    ScanConfig.BankConfig bankConfig = new ScanConfig.BankConfig(baseUrl, specUrl);
                    config.getBanks().add(bankConfig);
                    logger.info("[CONFIG_PARSER] Parsed bank - baseUrl: " + baseUrl + ", specUrl: " + specUrl);
                }
            }

            // Парсинг учетных данных
            if (jsonObject.has("credentials")) {
                JSONArray credentialsArray = jsonObject.getJSONArray("credentials");
                logger.info("[CONFIG_PARSER] Found " + credentialsArray.length() + " credential objects");

                for (int i = 0; i < credentialsArray.length(); i++) {
                    JSONObject credObj = credentialsArray.getJSONObject(i);
                    String username = credObj.getString("username");
                    String password = credObj.getString("password");

                    ScanConfig.UserCredentials userCred = new ScanConfig.UserCredentials(username, password);
                    config.getCredentials().add(userCred);
                    logger.info("[CONFIG_PARSER] Parsed credential - username: " + username + ", password: ***");
                }
            } else {
                // Если credentials отсутствуют в JSON, создаем их из токенов
                logger.info("[CONFIG_PARSER] No credentials in config, will use tokens directly");
            }

            // Устанавливаем bankId
            if (jsonObject.has("bankId")) {
                String bankId = jsonObject.getString("bankId");
                config.setBankId(bankId);
                logger.info("[CONFIG_PARSER] Set bankId from config: " + bankId);
            } else {
                // Вычисляем bankId из первого пользователя или используем по умолчанию
                if (!config.getCredentials().isEmpty()) {
                    String firstUsername = config.getCredentials().get(0).getUsername();
                    if (firstUsername != null && firstUsername.contains("-")) {
                        String calculatedBankId = firstUsername.split("-")[0];
                        config.setBankId(calculatedBankId);
                        logger.info("[CONFIG_PARSER] Calculated bankId from username: " + calculatedBankId);
                    } else {
                        config.setBankId("team172");
                        logger.info("[CONFIG_PARSER] Set default bankId: team172");
                    }
                } else {
                    config.setBankId("team172");
                    logger.info("[CONFIG_PARSER] Set default bankId: team172 (no credentials)");
                }
            }

            // Устанавливаем clientId из первого пользователя
            if (!config.getCredentials().isEmpty()) {
                String firstUsername = config.getCredentials().get(0).getUsername();
                config.setClientId(firstUsername);
                logger.info("[CONFIG_PARSER] Set clientId from first user: " + firstUsername);
            } else {
                config.setClientId("team172-1"); // значение по умолчанию
                logger.info("[CONFIG_PARSER] Set default clientId: team172-1");
            }

            // Устанавливаем clientSecret из первого пользователя
            if (!config.getCredentials().isEmpty()) {
                String firstPassword = config.getCredentials().get(0).getPassword();
                config.setClientSecret(firstPassword);
                logger.info("[CONFIG_PARSER] Set clientSecret from first user");
            } else {
                config.setClientSecret("password"); // значение по умолчанию
                logger.info("[CONFIG_PARSER] Set default clientSecret");
            }

            // Устанавливаем базовый URL из первого банка
            if (!config.getBanks().isEmpty()) {
                String firstBankUrl = config.getBanks().get(0).getBaseUrl();
                config.setBankBaseUrl(firstBankUrl);
                config.setTargetBaseUrl(firstBankUrl);
                logger.info("[CONFIG_PARSER] Set bankBaseUrl from first bank: " + firstBankUrl);
            }

            // Устанавливаем OpenAPI spec URL из первого банка
            if (!config.getBanks().isEmpty()) {
                String firstSpecUrl = config.getBanks().get(0).getSpecUrl();
                config.setOpenApiSpecUrl(firstSpecUrl);
                logger.info("[CONFIG_PARSER] Set openApiSpecUrl from first bank: " + firstSpecUrl);
            }

        } catch (Exception e) {
            logger.severe("[CONFIG_PARSER] Ошибка парсинга конфигурации: " + e.getMessage());
            throw new RuntimeException("Ошибка парсинга конфигурации", e);
        }

        return config;
    }
}