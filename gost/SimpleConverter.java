import java.io.*;
import java.security.*;
import java.util.*;

public class SimpleConverter {
    public static void main(String[] args) {
        try {
            System.out.println("=== Simple PFX to JKS Converter ===");
            
            // Загружаем PFX
            KeyStore pfxStore = KeyStore.getInstance("PKCS12", "SunJSSE");
            FileInputStream pfxStream = new FileInputStream("serf.pfx");
            
            System.out.print("Enter PFX password: ");
            char[] pfxPassword = System.console().readPassword();
            pfxStore.load(pfxStream, pfxPassword);
            
            System.out.println("✅ PFX loaded successfully");
            
            // Получаем список алиасов
            Enumeration<String> aliases = pfxStore.aliases();
            List<String> aliasList = Collections.list(aliases);
            System.out.println("Found aliases: " + aliasList);
            
            // Используем первый алиас для ключа
            String mainAlias = aliasList.get(0);
            System.out.println("Using alias: " + mainAlias);
            
            // Создаем JKS
            KeyStore jksStore = KeyStore.getInstance("JKS");
            jksStore.load(null, null);
            
            System.out.print("Enter JKS password: ");
            char[] jksPassword = System.console().readPassword();
            
            // Переносим ключ и цепочку сертификатов
            Key key = pfxStore.getKey(mainAlias, pfxPassword);
            java.security.cert.Certificate[] chain = pfxStore.getCertificateChain(mainAlias);
            
            jksStore.setKeyEntry(mainAlias, key, jksPassword, chain);
            System.out.println("✅ Key and certificate chain imported");
            
            // Сохраняем JKS
            FileOutputStream jksStream = new FileOutputStream("serf.jks");
            jksStore.store(jksStream, jksPassword);
            jksStream.close();
            
            System.out.println("✅ JKS file created: serf.jks");
            System.out.println("File size: " + new File("serf.jks").length() + " bytes");
            
        } catch (Exception e) {
            System.err.println("❌ Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
