package scanners.fuzzing;

import java.util.*;
import java.util.Base64;

public class ObfuscationEngine {

    private Random random = new Random();
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final String BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public List<String> obfuscatePayload(String payload) {
        List<String> obfuscated = new ArrayList<>();

        if (payload == null || payload.isEmpty()) {
            return obfuscated;
        }

        // Применяем различные методы обфускации
        obfuscated.add(urlEncode(payload));
        obfuscated.add(doubleUrlEncode(payload));
        obfuscated.add(base64Encode(payload));
        obfuscated.add(base32Encode(payload));
        obfuscated.add(base58Encode(payload));
        obfuscated.add(unicodeEncode(payload));
        obfuscated.add(htmlEntityEncode(payload));
        obfuscated.add(hexEncode(payload));
        obfuscated.add(mixedCase(payload));
        obfuscated.add(whitespaceObfuscate(payload));
        obfuscated.add(commentObfuscate(payload));

        // Комбинированные методы (2-3 уровня обфускации)
        obfuscated.add(urlEncode(base64Encode(payload)));
        obfuscated.add(unicodeEncode(urlEncode(payload)));
        obfuscated.add(mixedCase(base64Encode(payload)));
        obfuscated.add(hexEncode(urlEncode(payload)));

        return obfuscated;
    }

    private String urlEncode(String payload) {
        try {
            return java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return payload;
        }
    }

    private String doubleUrlEncode(String payload) {
        return urlEncode(urlEncode(payload));
    }

    private String base64Encode(String payload) {
        try {
            return Base64.getEncoder().encodeToString(payload.getBytes());
        } catch (Exception e) {
            return payload;
        }
    }

    private String base32Encode(String payload) {
        try {
            byte[] bytes = payload.getBytes();
            StringBuilder result = new StringBuilder();
            int buffer = 0;
            int bitsLeft = 0;

            for (byte b : bytes) {
                buffer = (buffer << 8) | (b & 0xFF);
                bitsLeft += 8;
                while (bitsLeft >= 5) {
                    int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                    result.append(BASE32_CHARS.charAt(index));
                    bitsLeft -= 5;
                }
            }

            if (bitsLeft > 0) {
                int index = (buffer << (5 - bitsLeft)) & 0x1F;
                result.append(BASE32_CHARS.charAt(index));
            }

            return result.toString();
        } catch (Exception e) {
            return payload;
        }
    }

    private String base58Encode(String payload) {
        try {
            byte[] bytes = payload.getBytes();
            long value = 0;
            for (byte b : bytes) {
                value = value * 256 + (b & 0xFF);
            }

            StringBuilder result = new StringBuilder();
            while (value > 0) {
                int remainder = (int) (value % 58);
                value /= 58;
                result.insert(0, BASE58_CHARS.charAt(remainder));
            }

            return result.toString();
        } catch (Exception e) {
            return payload;
        }
    }

    private String unicodeEncode(String payload) {
        StringBuilder sb = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (random.nextBoolean() && c > 127) {
                sb.append("\\u").append(String.format("%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String htmlEntityEncode(String payload) {
        return payload.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    private String hexEncode(String payload) {
        StringBuilder sb = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (random.nextBoolean()) {
                sb.append("\\x").append(String.format("%02x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String mixedCase(String payload) {
        StringBuilder sb = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (Character.isLetter(c)) {
                if (random.nextBoolean()) {
                    sb.append(Character.toUpperCase(c));
                } else {
                    sb.append(Character.toLowerCase(c));
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String whitespaceObfuscate(String payload) {
        String[] whitespaces = {" ", "\t", "\n", "\r", "%09", "%0A", "%0D"};
        StringBuilder sb = new StringBuilder();

        for (char c : payload.toCharArray()) {
            sb.append(c);
            if (random.nextDouble() < 0.3) {
                sb.append(whitespaces[random.nextInt(whitespaces.length)]);
            }
        }
        return sb.toString();
    }

    private String commentObfuscate(String payload) {
        String[] comments = {"/*", "*/", "--", "#", "//"};
        if (payload.contains(" ") && random.nextBoolean()) {
            String comment = comments[random.nextInt(comments.length)];
            return payload.replace(" ", comment + " " + comment);
        }
        return payload;
    }
}