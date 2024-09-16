package org.example;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;

import java.security.GeneralSecurityException;

import static java.nio.charset.StandardCharsets.UTF_8;

public class MessageAuthentication {

    private static final String KEY = """
            {
                "primaryKeyId": 691856985,
                "key": [{
                    "keyData": {
                        "typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
                        "keyMaterialType": "SYMMETRIC",
                        "value": "EgQIAxAgGiDZsmkTufMG/XlKlk9m7bqxustjUPT2YULEVm8mOp2mSA\\u003d\\u003d"
                    },
                    "outputPrefixType": "TINK",
                    "keyId": 691856985,
                    "status": "ENABLED"
                }]
            }""";

    public byte[] compute(String clearText) throws GeneralSecurityException {
        KeysetHandle keysetHandle = TinkJsonProtoKeysetFormat.parseKeyset(KEY, InsecureSecretKeyAccess.get());
        Mac mac = keysetHandle.getPrimitive(Mac.class);
        return mac.computeMac(clearText.getBytes(UTF_8));
    }

    public boolean verify(byte[] messageDigest, String clearText) throws GeneralSecurityException {
        KeysetHandle keysetHandle = TinkJsonProtoKeysetFormat.parseKeyset(KEY, InsecureSecretKeyAccess.get());
        Mac mac = keysetHandle.getPrimitive(Mac.class);
        try {
            mac.verifyMac(messageDigest, clearText.getBytes(UTF_8));
            return true;
        } catch (GeneralSecurityException ex) {
            return false;
        }
    }

}
