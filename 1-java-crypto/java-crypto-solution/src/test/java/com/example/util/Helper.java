package com.example.util;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;

public final class Helper {

    public static final Logger LOGGER = LoggerFactory.getLogger(Helper.class);

    public static void printText(String name, byte[] bytes) {
        LOGGER.info("{}: {}", name, new String(bytes));
        LOGGER.info("{} length: {} bytes, {} bits", name, bytes.length, bytes.length * 8);
        LOGGER.info("\r\n");
    }

    public static void printByteArray(String name, byte[] bytes) {
        LOGGER.info("{}: {}", name, Hex.encodeHexString(bytes));
        LOGGER.info("{} length: {} bytes, {} bits", name, bytes.length, bytes.length * 8);
        LOGGER.info("\r\n");
    }

    public static String byteArrayToHexString(Key key) {
        return byteArrayToHexString(key.getEncoded());
    }

    public static String byteArrayToHexString(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte value : b) {
            int v = value & 0xff;
            if (v < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(v));
        }
        return sb.toString().toUpperCase();
    }
}
