package org.example;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;

import java.security.GeneralSecurityException;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Encryption {

    private static final String KEY = """
            {
              "primaryKeyId":1931667682,
              "key":[{
                "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "value":"GhD+9l0RANZjzZEZ8PDp7LRW",
                  "keyMaterialType":"SYMMETRIC"},
                "status":"ENABLED",
                "keyId":1931667682,
                "outputPrefixType":"TINK"
              }]
            }""";

    public byte[] encrypt(String clearText) throws GeneralSecurityException {
        KeysetHandle keysetHandle = TinkJsonProtoKeysetFormat.parseKeyset(KEY, InsecureSecretKeyAccess.get());
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        return aead.encrypt(clearText.getBytes(UTF_8), "123".getBytes(UTF_8));
    }

    public String decrypt(byte[] cipherText) throws GeneralSecurityException {
        KeysetHandle keysetHandle = TinkJsonProtoKeysetFormat.parseKeyset(KEY, InsecureSecretKeyAccess.get());
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        return new String(aead.decrypt(cipherText, "123".getBytes(UTF_8)), UTF_8);
    }

}
