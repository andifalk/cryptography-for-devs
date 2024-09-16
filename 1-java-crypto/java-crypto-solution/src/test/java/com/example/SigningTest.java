package com.example;

import com.example.util.Helper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#signature-algorithms
public class SigningTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(SigningTest.class);

    @BeforeAll
    static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("asymmetric signing with RSA")
    @Test
    public void testSigningData() throws GeneralSecurityException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(2048);
        KeyPair keyPair = kpGen.generateKeyPair();
        Helper.printByteArray("private key", keyPair.getPrivate().getEncoded());
        Helper.printByteArray("public key", keyPair.getPublic().getEncoded());

        String dataToSign = "Data that should not be changed!!!";

        // Sign data

        Signature signatureWithRsa = Signature.getInstance("SHA256withRSA");
        signatureWithRsa.initSign(keyPair.getPrivate());
        signatureWithRsa.update(dataToSign.getBytes(UTF_8));
        byte[] signature = signatureWithRsa.sign();
        Helper.printByteArray("signature", signature);

        // Verify data

        String receivedData = "Data that should not be changed!!!";
        Signature signatureVerificationWithRsa = Signature.getInstance("SHA256withRSA");
        signatureVerificationWithRsa.initVerify(keyPair.getPublic());
        signatureVerificationWithRsa.update(receivedData.getBytes(UTF_8));

        assertThat(signatureVerificationWithRsa.verify(signature)).isTrue();
    }
}
