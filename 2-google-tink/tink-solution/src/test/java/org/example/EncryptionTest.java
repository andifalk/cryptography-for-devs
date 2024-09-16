package org.example;

import com.google.crypto.tink.aead.AeadConfig;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static org.assertj.core.api.Assertions.assertThat;

public class EncryptionTest {

    public EncryptionTest() throws GeneralSecurityException {
        AeadConfig.register();
    }

    @Test
    void testEncryption() throws GeneralSecurityException {
        Encryption encryption = new Encryption();
        byte[] ciphertext = encryption.encrypt("Hello World");
        assertThat(ciphertext).isNotNull();
        String clearText = encryption.decrypt(ciphertext);
        assertThat(clearText).as("Decrypted text is expected clear text").isEqualTo("Hello World");
    }
}
