import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class SimplePfxConverter {
    public static void main(String[] args) {
        try {
            // Пробуем разные провайдеры
            String[] providers = {
                "SunJSSE", "SunPKCS11", "SunMSCAPI", "Apple"
            };
            
            for (String provider : providers) {
                try {
                    System.out.println("Trying provider: " + provider);
                    convertWithProvider(provider);
                    break;
                } catch (Exception e) {
                    System.out.println("Provider " + provider + " failed: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void convertWithProvider(String providerName) throws Exception {
        KeyStore pfxStore = KeyStore.getInstance("PKCS12", providerName);
        FileInputStream pfxStream = new FileInputStream("serf.pfx");
        
        System.out.print("Enter PFX password: ");
        char[] pfxPassword = System.console().readPassword();
        pfxStore.load(pfxStream, pfxPassword);
        
        System.out.println("PFX loaded successfully with provider: " + providerName);
        System.out.println("Aliases in keystore: " + Collections.list(pfxStore.aliases()));
    }
}
