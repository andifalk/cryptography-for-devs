package com.example;

import com.example.util.Helper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

// https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#cipher-algorithms
// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#cipher-algorithm-modes
// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#cipher-algorithm-paddings
// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#securerandom-number-generation-algorithms
public class SymmetricEncryptionTest {

    @BeforeAll
    static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("block repeating pattern with AES/ECB (Electronic Codebook Mode)")
    @Test
    public void testAesEcb() throws GeneralSecurityException {

        // 128, 192 or 256 as key size
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        Helper.printByteArray("secretKey", secretKey.getEncoded());
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] clearText = "Test123_".repeat(8).getBytes(UTF_8);
        Helper.printText("clearText", clearText);
        byte[] encryptedText = cipher.doFinal(clearText);
        Helper.printByteArray("encryptedText", encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedText = cipher.doFinal(encryptedText);
        assertThat(decryptedText).isEqualTo(clearText);
        Helper.printText("decryptedText", decryptedText);
    }

    @DisplayName("block chaining pattern with AES/CBC (Cipher Block Chaining Mode)")
    @Test
    public void testAesCbc() throws GeneralSecurityException {

        // 128, 192 or 256 as key size
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        Helper.printByteArray("secretKey", secretKey.getEncoded());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] random = new byte[16];
        secureRandom.nextBytes(random);
        IvParameterSpec ivSpec = new IvParameterSpec(random);
        Helper.printByteArray("ivSpec", random);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] clearText = "Test123_".repeat(8).getBytes(UTF_8);
        Helper.printText("clearText", clearText);
        byte[] encryptedText = cipher.doFinal(clearText);
        Helper.printByteArray("encryptedText", encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedText = cipher.doFinal(encryptedText);
        assertThat(decryptedText).isEqualTo(clearText);
        Helper.printText("decryptedText", decryptedText);
    }

    @DisplayName("galois/counter with AES/GCM (Galois/Counter Mode)")
    @Test
    public void testAesGcm() throws GeneralSecurityException {

        // 128, 192 or 256 as key size
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        Helper.printByteArray("secretKey", secretKey.getEncoded());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] random = new byte[16];
        secureRandom.nextBytes(random);
        IvParameterSpec ivSpec = new IvParameterSpec(random);
        Helper.printByteArray("ivSpec", random);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, ivSpec.getIV()));
        byte[] clearText = "Test123_".repeat(8).getBytes(UTF_8);
        Helper.printText("clearText", clearText);
        byte[] encryptedText = cipher.doFinal(clearText);
        Helper.printByteArray("encryptedText", encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, ivSpec.getIV()));
        byte[] decryptedText = cipher.doFinal(encryptedText);
        assertThat(decryptedText).isEqualTo(clearText);
        Helper.printText("decryptedText", decryptedText);
    }

}
