package org.example;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static org.assertj.core.api.Assertions.assertThat;

public class MessageAuthenticationTest {

    public MessageAuthenticationTest() throws GeneralSecurityException {
        AeadConfig.register();
        MacConfig.register();
    }

    @Test
    void testMac() throws GeneralSecurityException {
        MessageAuthentication messageAuthentication = new MessageAuthentication();
        byte[] mac = messageAuthentication.compute("Hello World");
        assertThat(mac).isNotNull();
        assertThat(messageAuthentication.verify(mac, "Hello World")).isTrue();
    }
}
