// InsecureExample.java
// Exemplos: MD5, SHA-1, AES/ECB, RSA 1024 bits (inseguro)

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class InsecureExample {

    // Hardcoded key (insecure)
    private static final byte[] HARDCODED_KEY = "0123456789abcdef".getBytes(); // 16 bytes

    public static void main(String[] args) throws Exception {
        String message = "segredo super importante";

        // MD5 (inseguro)
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] md5Digest = md5.digest(message.getBytes());
        System.out.println("MD5: " + Base64.getEncoder().encodeToString(md5Digest));

        // SHA-1 (inseguro)
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Digest = sha1.digest(message.getBytes());
        System.out.println("SHA1: " + Base64.getEncoder().encodeToString(sha1Digest));

        // AES in ECB mode (insecure: ECB leaks patterns)
        SecretKeySpec keySpec = new SecretKeySpec(HARDCODED_KEY, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB usado aqui
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        System.out.println("AES-ECB (base64): " + Base64.getEncoder().encodeToString(encrypted));

        // RSA with small key size (insecure, <2048)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024); // <<-- inseguro: chave RSA de 1024 bits
        KeyPair kp = kpg.generateKeyPair();
        Signature s = Signature.getInstance("SHA1withRSA"); // SHA-1 with RSA (insecure sig hash)
        s.initSign(kp.getPrivate());
        s.update(message.getBytes());
        byte[] sig = s.sign();
        System.out.println("RSA-1024 signature (base64): " + Base64.getEncoder().encodeToString(sig));
    }
}
