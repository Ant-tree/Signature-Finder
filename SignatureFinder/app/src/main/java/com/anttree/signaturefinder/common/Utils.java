package com.anttree.signaturefinder.common;

import android.util.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {

    public static String intoHexString(byte[] bytes) {
        StringBuilder signHex = new StringBuilder();
        for (byte signByte : bytes) {
            signHex.append(String.format("%02x", signByte));
        }
        return signHex.toString();
    }

    public static byte[] fileReader(File file, int offset, int length) {
        byte[] data = new byte[length];
        //ByteBuffer data = ByteBuffer.allocateDirectly(length)

        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            if (offset > 0) {
                fileInputStream.getChannel().position(offset);
            }
            //int resultLength = fileInputStream.getChannel().read(data, length);
            int resultLength = fileInputStream.read(data, 0, length);
            // if read bytes length and cache file size doesn't match
            // possible assumption - not available to read full file contents
            if (resultLength != length) {
                //Something went wrong!
                return null;
            }

        } catch (IOException e) {
            //Any exception while reading
            return null;
        }

        return data;
    }

    public static String digestInBase64(int digestSort, byte[] target) {
        String algorithm;

        switch (digestSort) {
            case 0:
                algorithm = "SHA-1";
                break;
            case 1:
                algorithm = "SHA-256";
                break;
            case 2:
                algorithm = "SHA-384";
                break;
            case 3:
                algorithm = "SHA-512";
                break;
            default: //Undefined, digest sort was entered
                return null;
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hash = digest.digest(target);
            return Base64.encodeToString(hash, Base64.DEFAULT).trim();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

}
