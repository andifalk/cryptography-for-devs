package com.example;

import com.example.util.Helper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

// https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#cipher-algorithms
// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#keypairgenerator-algorithms
public class AsymmetricEncryptionTest {

    @BeforeAll
    static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("asymmetric encryption/decryption with RSA")
    @Test
    public void testRsa() throws GeneralSecurityException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(2048);
        KeyPair keyPair = kpGen.generateKeyPair();
        Helper.printByteArray("private key", keyPair.getPrivate().getEncoded());
        Helper.printByteArray("public key", keyPair.getPublic().getEncoded());

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] clearText = "Test123_".repeat(8).getBytes(UTF_8);
        Helper.printText("clearText", clearText);
        byte[] encryptedText = cipher.doFinal(clearText);
        Helper.printByteArray("encryptedText", encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedText = cipher.doFinal(encryptedText);
        assertThat(decryptedText).isEqualTo(clearText);
        Helper.printText("decryptedText", decryptedText);
    }

    @DisplayName("asymmetric encryption/decryption with Elliptic Curve")
    @Test
    public void testEcies() throws GeneralSecurityException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");
        // https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#parameterspec-names
        kpGen.initialize(new ECGenParameterSpec("secp521r1"));
        KeyPair keyPair = kpGen.generateKeyPair();
        Helper.printByteArray("private key", keyPair.getPrivate().getEncoded());
        Helper.printByteArray("public key", keyPair.getPublic().getEncoded());

        Cipher cipher = Cipher.getInstance("ECIES");

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] clearText = "Test123_".repeat(8).getBytes(UTF_8);
        Helper.printText("clearText", clearText);
        byte[] encryptedText = cipher.doFinal(clearText);
        Helper.printByteArray("encryptedText", encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedText = cipher.doFinal(encryptedText);
        assertThat(decryptedText).isEqualTo(clearText);
        Helper.printText("decryptedText", decryptedText);
    }

    @DisplayName("exchange with Diffie-Hellman KeyAgreement algorithm")
    @Test
    public void testDh() throws GeneralSecurityException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DiffieHellman");
        kpGen.initialize(512);
        KeyPair keyPair = kpGen.generateKeyPair();
        Helper.printByteArray("private key", keyPair.getPrivate().getEncoded());
        Helper.printByteArray("public key", keyPair.getPublic().getEncoded());

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
        keyAgreement.init(keyPair.getPrivate());
        Key phaseKey = keyAgreement.doPhase(keyPair.getPublic(), false);

        Helper.printByteArray("phaseKey", phaseKey.getEncoded());
    }
}
