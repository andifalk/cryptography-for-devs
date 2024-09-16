package com.example;

import com.example.util.Helper;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;

import static org.assertj.core.api.Assertions.assertThat;

class HashingTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(HashingTest.class);

    @BeforeAll
    static void init() {
        Security.addProvider(new BouncyCastleProvider());
        Provider[] providers = Security.getProviders();
        LOGGER.info("Providers");
        LOGGER.info("===========================");
        for (Provider provider : providers) {
            LOGGER.info(provider.getName());
        }
        LOGGER.info("===========================");
        LOGGER.info("");
    }

    @Test
    void oneWayOnly() throws NoSuchAlgorithmException, NoSuchProviderException {
        hashText("The quick brown fox jumped over the lazy dog.");
    }

    @Test
    void deterministic() throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] hash1 = hashText("The quick brown fox jumped over the lazy dog.");
        byte[] hash2 = hashText("The quick brown fox jumped over the lazy dog.");
        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void pseudorandom() throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] hash1 = hashText("The quick brown fox jumped over the lazy dog.");
        byte[] hash2 = hashText("The quick brown fox jumped ower the lazy dog.");
        assertThat(hash1).isNotEqualTo(hash2);
    }

    @Test
    void fixedLength() throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] hash1 = hashText("The quick brown fox jumped over the lazy dog.");
        byte[] hash2 = hashText("The quick brown fox jumped over the lazy dog and a lot more stuff happened after that.");
        assertThat(hash1.length).isEqualTo(hash2.length);
    }

    @Test
    void testMd5Collision() throws GeneralSecurityException, DecoderException {
        byte[] data1 = Hex.decodeHex("4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2");
        byte[] data2 = Hex.decodeHex("4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2");

        assertThat(data1).isNotEqualTo(data2);
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] digest1 = messageDigest.digest(data1);
        Helper.printByteArray("Digest1", digest1);
        byte[] digest2 = messageDigest.digest(data2);
        Helper.printByteArray("Digest2", digest2);
        assertThat(digest1).as("Should not have a collision").isNotEqualTo(digest2);
    }

    private byte[] hashText(String data) throws NoSuchAlgorithmException, NoSuchProviderException {
        LOGGER.info("Input: {}", data);
        // See https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#messagedigest-algorithms
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-256");
        //MessageDigest messageDigest = MessageDigest.getInstance("SHA3-256", "BC");
        byte[] digest = messageDigest.digest(data.getBytes());
        Helper.printByteArray("Digest", digest);
        return digest;
    }
}
