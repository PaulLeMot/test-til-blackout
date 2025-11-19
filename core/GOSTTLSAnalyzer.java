package core;

import javax.net.ssl.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.*;
import java.util.*;
import java.net.URL;
import java.net.URI;
import java.io.IOException;

public class GOSTTLSAnalyzer {
    private final String targetUrl;
    private final List<Vulnerability> vulnerabilities;

    // ГОСТ алгоритмы
    private static final Set<String> GOST_CIPHERS = Set.of(
            "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
            "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
            "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"
    );

    private static final Set<String> REQUIRED_GOST_OIDS = Set.of(
            "1.2.643.7.1.1.1.1",  // ГОСТ Р 34.10-2012 256 бит
            "1.2.643.7.1.1.1.2",  // ГОСТ Р 34.10-2012 512 бит
            "1.2.643.2.2.19",     // ГОСТ Р 34.10-2001
            "1.2.643.7.1.1.2.1",  // Кузнечик
            "1.2.643.7.1.1.2.2"   // Магма
    );

    public GOSTTLSAnalyzer(String targetUrl) {
        this.targetUrl = targetUrl;
        this.vulnerabilities = new ArrayList<>();
    }

    public List<Vulnerability> analyze() {
        System.out.println("Запуск анализа ГОСТ и TLS безопасности...");

        try {
            analyzeTLSConfiguration();
            analyzeCertificateCompliance();
            analyzeProtocolSupport();
            analyzeRussianCompliance();
        } catch (Exception e) {
            System.err.println("Ошибка при анализе ГОСТ/TLS: " + e.getMessage());
            addVulnerability(
                    "Ошибка анализа TLS/ГОСТ",
                    "Не удалось выполнить анализ TLS конфигурации: " + e.getMessage(),
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }

        System.out.println("Анализ ГОСТ/TLS завершен. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Анализ общей конфигурации TLS
     */
    private void analyzeTLSConfiguration() {
        try {
            URI uri = new URI(targetUrl);
            String host = uri.getHost();
            int port = uri.getPort() != -1 ? uri.getPort() : 443;

            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {

                // Анализ поддерживаемых протоколов
                String[] supportedProtocols = socket.getSupportedProtocols();
                String[] enabledProtocols = socket.getEnabledProtocols();

                analyzeProtocols(supportedProtocols, enabledProtocols);

                // Анализ шифров
                String[] supportedCiphers = socket.getSupportedCipherSuites();
                String[] enabledCiphers = socket.getEnabledCipherSuites();

                analyzeCiphers(supportedCiphers, enabledCiphers);

                // Проверка сертификата
                analyzeServerCertificate(socket);
            }

        } catch (Exception e) {
            addVulnerability(
                    "Не удалось установить TLS соединение",
                    "Ошибка подключения к " + targetUrl + ": " + e.getMessage(),
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }
    }

    /**
     * Анализ поддерживаемых протоколов
     */
    private void analyzeProtocols(String[] supported, String[] enabled) {
        Set<String> enabledSet = new HashSet<>(Arrays.asList(enabled));

        // Проверка устаревших протоколов
        if (enabledSet.contains("SSLv3") || enabledSet.contains("SSLv2")) {
            addVulnerability(
                    "Поддержка устаревших SSL протоколов",
                    "Сервер поддерживает устаревшие и небезопасные SSL протоколы",
                    Vulnerability.Severity.HIGH,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }

        if (enabledSet.contains("TLSv1")) {
            addVulnerability(
                    "Поддержка TLS 1.0",
                    "TLS 1.0 является устаревшим и уязвимым протоколом",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }

        if (enabledSet.contains("TLSv1.1")) {
            addVulnerability(
                    "Поддержка TLS 1.1",
                    "TLS 1.1 считается устаревшим и должен быть отключен",
                    Vulnerability.Severity.LOW,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }

        // Проверка современных протоколов
        if (!enabledSet.contains("TLSv1.2") && !enabledSet.contains("TLSv1.3")) {
            addVulnerability(
                    "Отсутствуют современные TLS протоколы",
                    "Сервер не поддерживает TLS 1.2 или TLS 1.3",
                    Vulnerability.Severity.HIGH,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }
    }

    /**
     * Анализ шифров
     */
    private void analyzeCiphers(String[] supported, String[] enabled) {
        Set<String> enabledSet = new HashSet<>(Arrays.asList(enabled));

        // Поиск слабых шифров
        List<String> weakCiphers = findWeakCiphers(enabledSet);
        if (!weakCiphers.isEmpty()) {
            addVulnerability(
                    "Обнаружены слабые шифры",
                    "Сервер использует слабые или устаревшие шифры: " + String.join(", ", weakCiphers),
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }

        // Проверка ГОСТ шифров
        boolean hasGostCiphers = enabledSet.stream().anyMatch(this::isGostCipher);
        if (!hasGostCiphers) {
            addVulnerability(
                    "Отсутствуют ГОСТ шифры",
                    "Сервер не поддерживает ГОСТ алгоритмы шифрования",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }

        // Проверка современных шифров
        boolean hasStrongCiphers = enabledSet.stream().anyMatch(this::isStrongCipher);
        if (!hasStrongCiphers) {
            addVulnerability(
                    "Отсутствуют современные шифры",
                    "Сервер не использует современные криптографические алгоритмы",
                    Vulnerability.Severity.HIGH,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }
    }

    /**
     * Анализ сертификата сервера
     */
    private void analyzeServerCertificate(SSLSocket socket) {
        try {
            socket.startHandshake();

            SSLSession session = socket.getSession();
            Certificate[] certs = session.getPeerCertificates();

            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                X509Certificate cert = (X509Certificate) certs[0];
                analyzeCertificate(cert);
            }

        } catch (SSLException e) {
            addVulnerability(
                    "Ошибка TLS handshake",
                    "Не удалось установить безопасное соединение: " + e.getMessage(),
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        } catch (Exception e) {
            System.err.println("Ошибка при анализе сертификата: " + e.getMessage());
        }
    }

    /**
     * Анализ соответствия сертификата
     */
    private void analyzeCertificateCompliance() {
        // Проверка использования российских сертификатов
        addVulnerability(
                "Требуется проверка российских сертификатов",
                "Для полного соответствия ГОСТ требуется использовать сертификаты, " +
                        "выпущенные аккредитованными УЦ в соответствии с российскими стандартами",
                Vulnerability.Severity.MEDIUM,
                Vulnerability.Category.OWASP_API8_SM
        );
    }

    /**
     * Анализ соответствия российским стандартам
     */
    private void analyzeRussianCompliance() {
        // Проверка требований ФСТЭК и ФСБ
        checkFSTECCompliance();
        checkFSBCompliance();
        checkBankOfRussiaCompliance();
    }

    private void checkFSTECCompliance() {
        addVulnerability(
                "Требуется проверка соответствия ФСТЭК",
                "Необходимо проверить соответствие требованиям ФСТЭК России по защите информации",
                Vulnerability.Severity.MEDIUM,
                Vulnerability.Category.OWASP_API8_SM
        );
    }

    private void checkFSBCompliance() {
        addVulnerability(
                "Требуется проверка лицензии ФСБ",
                "Для использования криптографии в РФ требуется лицензия ФСБ",
                Vulnerability.Severity.MEDIUM,
                Vulnerability.Category.OWASP_API8_SM
        );
    }

    private void checkBankOfRussiaCompliance() {
        addVulnerability(
                "Требуется проверка соответствия ЦБ РФ",
                "Для финансовых организаций необходимо соответствие стандартам Банка России",
                Vulnerability.Severity.MEDIUM,
                Vulnerability.Category.OWASP_API8_SM
        );
    }

    /**
     * Анализ конкретного сертификата
     */
    private void analyzeCertificate(X509Certificate cert) {
        try {
            // Проверка срока действия
            cert.checkValidity();

            // Проверка алгоритма подписи
            String sigAlg = cert.getSigAlgName().toUpperCase();
            if (!sigAlg.contains("GOST")) {
                addVulnerability(
                        "Сертификат не использует ГОСТ алгоритмы",
                        "Алгоритм подписи сертификата: " + sigAlg + ". Рекомендуется использование ГОСТ Р 34.10-2012",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API8_SM
                );
            }

            // Проверка издателя
            String issuer = cert.getIssuerX500Principal().getName();
            if (!isRussianCA(issuer)) {
                addVulnerability(
                        "Сертификат выпущен не российским УЦ",
                        "Издатель сертификата: " + issuer + ". Для соответствия ГОСТ рекомендуется использовать российские УЦ",
                        Vulnerability.Severity.LOW,
                        Vulnerability.Category.OWASP_API8_SM
                );
            }

            // Проверка ключа
            PublicKey publicKey = cert.getPublicKey();
            analyzePublicKey(publicKey);

        } catch (Exception e) {
            addVulnerability(
                    "Проблема с сертификатом сервера",
                    "Ошибка при проверке сертификата: " + e.getMessage(),
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }
    }

    private void analyzePublicKey(PublicKey publicKey) {
        String algorithm = publicKey.getAlgorithm().toUpperCase();

        if (!algorithm.contains("GOST")) {
            addVulnerability(
                    "Открытый ключ не использует ГОСТ",
                    "Алгоритм открытого ключа: " + algorithm + ". Рекомендуется ГОСТ Р 34.10-2012",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }

        // Проверка длины ключа
        int keyLength = getKeyLength(publicKey);
        if (keyLength < 256) {
            addVulnerability(
                    "Недостаточная длина ключа",
                    "Длина ключа: " + keyLength + " бит. Для ГОСТ рекомендуется 256 бит или более",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }
    }

    // Вспомогательные методы
    private List<String> findWeakCiphers(Set<String> ciphers) {
        List<String> weak = new ArrayList<>();

        for (String cipher : ciphers) {
            if (isWeakCipher(cipher)) {
                weak.add(cipher);
            }
        }

        return weak;
    }

    private boolean isWeakCipher(String cipher) {
        return cipher.toUpperCase().contains("NULL") ||
                cipher.toUpperCase().contains("ANON") ||
                cipher.toUpperCase().contains("EXPORT") ||
                cipher.toUpperCase().contains("RC4") ||
                cipher.toUpperCase().contains("DES") ||
                cipher.toUpperCase().contains("MD5");
    }

    private boolean isGostCipher(String cipher) {
        String cipherUpper = cipher.toUpperCase();
        return GOST_CIPHERS.stream().anyMatch(cipherUpper::contains);
    }

    private boolean isStrongCipher(String cipher) {
        String cipherUpper = cipher.toUpperCase();
        return cipherUpper.contains("AES_256") ||
                cipherUpper.contains("CHACHA20") ||
                cipherUpper.contains("GOST") ||
                (cipherUpper.contains("ECDHE") && cipherUpper.contains("RSA") && cipherUpper.contains("AES_128"));
    }

    private boolean isRussianCA(String issuer) {
        return issuer.toUpperCase().contains("RUSSIAN") ||
                issuer.toUpperCase().contains("RUSSIA") ||
                issuer.toUpperCase().contains("RU") ||
                issuer.contains("Россия") ||
                issuer.contains("РОССИЯ");
    }

    private int getKeyLength(PublicKey publicKey) {
        // Простая оценка длины ключа
        String algorithm = publicKey.getAlgorithm().toUpperCase();

        if (algorithm.contains("RSA")) {
            return publicKey.getEncoded().length * 8;
        } else if (algorithm.contains("GOST")) {
            return 256; // Стандартная длина для ГОСТ
        } else if (algorithm.contains("ECDSA")) {
            return 256; // Минимальная для ECDSA
        }

        return 0;
    }

    private void analyzeProtocolSupport() {
        // Дополнительная проверка поддержки протоколов
        addVulnerability(
                "Рекомендация по протоколам",
                "Для максимальной безопасности рекомендуется: TLS 1.2/TLS 1.3 с ГОСТ шифрами",
                Vulnerability.Severity.LOW,
                Vulnerability.Category.OWASP_API8_SM
        );
    }

    private void addVulnerability(String title, String description,
                                  Vulnerability.Severity severity, Vulnerability.Category category) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle(title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(category);
        vuln.setEvidence("Обнаружено при анализе TLS/ГОСТ конфигурации");

        // Специфические рекомендации для TLS/ГОСТ
        List<String> recommendations = Arrays.asList(
                "Внедрить поддержку ГОСТ алгоритмов шифрования",
                "Отключить устаревшие протоколы (SSLv3, TLS 1.0, TLS 1.1)",
                "Использовать сертификаты от аккредитованных российских УЦ",
                "Настроить приоритет шифров: ГОСТ → AES_256 → другие",
                "Регулярно обновлять TLS конфигурацию в соответствии с российскими стандартами",
                "Провести сертификацию СКЗИ в ФСБ России"
        );
        vuln.setRecommendations(recommendations);

        vulnerabilities.add(vuln);
    }
}