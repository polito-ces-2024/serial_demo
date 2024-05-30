package org.example;
import com.fazecast.jSerialComm.SerialPort;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.concurrent.*;
import java.security.KeyFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
public class Main {

    public static String arr(byte[] m) {

        StringBuilder sb = new StringBuilder();
        for (byte b : m) {
            sb.append(String.format("0x%02X, ", b));
        }
        return "[" + sb.toString() + "]";
    }

    public static void main(String[] args) {
        //System.out.println(HardwareDetector.detectHardware());
        try {

        String pubkey = new String(Main.class.getClassLoader().getResourceAsStream("public-key.pem").readAllBytes());
        System.out.println(pubkey);
        String privKey = new String(Main.class.getClassLoader().getResourceAsStream("private-key.pem").readAllBytes());
        System.out.println(privKey);
        byte[] byteArray = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            byte[] inputCipherBytes = new byte[] {
                    (byte)0x00, (byte)0x3d, (byte)0x29, (byte)0x31, (byte)0x01, (byte)0xfa, (byte)0x6b, (byte)0xea,
                    (byte)0x91, (byte)0x6a, (byte)0xcf, (byte)0x49, (byte)0x54, (byte)0xd2, (byte)0xd5, (byte)0xcc,
                    (byte)0xff, (byte)0xe9, (byte)0x69, (byte)0xac, (byte)0xa3, (byte)0x30, (byte)0xcb, (byte)0x45,
                    (byte)0x39, (byte)0x38, (byte)0x09, (byte)0x80, (byte)0x70, (byte)0xf0, (byte)0xd9, (byte)0x4f,
                    (byte)0x66, (byte)0xb1, (byte)0xcb, (byte)0xc3, (byte)0x45, (byte)0xc3, (byte)0x2d, (byte)0x7b,
                    (byte)0xcd, (byte)0x7b, (byte)0x16, (byte)0x71, (byte)0xd9, (byte)0x7e, (byte)0xe9, (byte)0x89,
                    (byte)0x2c, (byte)0x59, (byte)0x0b, (byte)0x2b, (byte)0x03, (byte)0x3d, (byte)0xf6, (byte)0x7e,
                    (byte)0x9d, (byte)0x59, (byte)0x1c, (byte)0xf7, (byte)0x32, (byte)0xc7, (byte)0xbc, (byte)0xa3,
                    (byte)0xee, (byte)0x46, (byte)0x2e, (byte)0xd3, (byte)0x4b, (byte)0x5c, (byte)0x7b, (byte)0x4b,
                    (byte)0x8c, (byte)0xec, (byte)0xdb, (byte)0xf1, (byte)0xec, (byte)0xc7, (byte)0x7f, (byte)0x64,
                    (byte)0x8d, (byte)0x2c, (byte)0x09, (byte)0x48, (byte)0x4b, (byte)0x65, (byte)0xcc, (byte)0xc3,
                    (byte)0xf5, (byte)0xee, (byte)0x10, (byte)0x2e, (byte)0x41, (byte)0xc4, (byte)0xc7, (byte)0xb7,
                    (byte)0x9c, (byte)0xbd, (byte)0x27, (byte)0x7c, (byte)0x46, (byte)0xf3, (byte)0xc7, (byte)0x12,
                    (byte)0x8c, (byte)0x6b, (byte)0x49, (byte)0xa0, (byte)0xbf, (byte)0xd5, (byte)0xf6, (byte)0x3c,
                    (byte)0xca, (byte)0x4d, (byte)0x98, (byte)0x91, (byte)0x11, (byte)0xc5, (byte)0xef, (byte)0x1f,
                    (byte)0x14, (byte)0x01, (byte)0x47, (byte)0x91, (byte)0x3f, (byte)0x48, (byte)0x7a, (byte)0x81,
                    (byte)0x61, (byte)0x03, (byte)0xc1, (byte)0x31, (byte)0xc2, (byte)0x27, (byte)0x71, (byte)0x42,
                    (byte)0x31, (byte)0xc9, (byte)0x74, (byte)0xe4, (byte)0x86, (byte)0x53, (byte)0x45, (byte)0x74,
                    (byte)0x7b, (byte)0x19, (byte)0xdd, (byte)0xc7, (byte)0xbd, (byte)0x37, (byte)0xfa, (byte)0x12,
                    (byte)0x49, (byte)0xce, (byte)0x36, (byte)0x3e, (byte)0xf9, (byte)0x21, (byte)0x71, (byte)0x6a,
                    (byte)0x54, (byte)0x24, (byte)0xaa, (byte)0x2c, (byte)0x41, (byte)0xda, (byte)0xd7, (byte)0x44,
                    (byte)0x1a, (byte)0x9b, (byte)0xdb, (byte)0x51, (byte)0x0c, (byte)0x4e, (byte)0x99, (byte)0x8b,
                    (byte)0x87, (byte)0xe4, (byte)0xbb, (byte)0x6f, (byte)0x3d, (byte)0xba, (byte)0x38, (byte)0xf9,
                    (byte)0x14, (byte)0x4d, (byte)0x27, (byte)0xf8, (byte)0x2f, (byte)0x77, (byte)0xb1, (byte)0x71,
                    (byte)0x8d, (byte)0x6d, (byte)0x3c, (byte)0xd6, (byte)0xa0, (byte)0xe3, (byte)0xf6, (byte)0x2a,
                    (byte)0x1b, (byte)0x70, (byte)0x74, (byte)0xd1, (byte)0x8b, (byte)0x0f, (byte)0x4e, (byte)0x9d,
                    (byte)0x03, (byte)0xda, (byte)0xec, (byte)0x09, (byte)0x97, (byte)0x42, (byte)0x1f, (byte)0xbe,
                    (byte)0x73, (byte)0x9b, (byte)0xcc, (byte)0x61, (byte)0x68, (byte)0xfa, (byte)0x99, (byte)0x37,
                    (byte)0x2e, (byte)0x1d, (byte)0x9a, (byte)0x2b, (byte)0x2b, (byte)0x8f, (byte)0xa4, (byte)0x3a,
                    (byte)0xe4, (byte)0xff, (byte)0x9e, (byte)0xd4, (byte)0x57, (byte)0x26, (byte)0x91, (byte)0xcd,
                    (byte)0x4a, (byte)0x76, (byte)0xbd, (byte)0xc3, (byte)0x35, (byte)0x0d, (byte)0x5c, (byte)0x14,
                    (byte)0xb4, (byte)0x14, (byte)0x03, (byte)0x73, (byte)0x47, (byte)0x0d, (byte)0x13, (byte)0x43
            };
            String sanitizedPub = pubkey.
                replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");


            String sanitizedPriv = privKey.
                    replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");
        //System.out.println("priv: " + sanitizedPriv);
            System.out.println("Cypher is " + inputCipherBytes.length);
            byte[] encodedPriv = Base64.getDecoder().decode(sanitizedPriv);

        byte[] encoded = Base64.getDecoder().decode(sanitizedPub);
        System.out.println("Public key is " + encoded.length + " bytes");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);

            PKCS8EncodedKeySpec privatekeySpec = new PKCS8EncodedKeySpec(encodedPriv);

            RSAPublicKey pubfinal = (RSAPublicKey) keyFactory.generatePublic(keySpec);
            RSAPrivateKey privfinal = (RSAPrivateKey) keyFactory.generatePrivate(privatekeySpec);
            System.out.println("Cipher" +arr(inputCipherBytes));
            Cipher cipherDecrypt = Cipher.getInstance("RSA/ECB/OAEPWITHSHA1ANDMGF1PADDING");
            cipherDecrypt.init(Cipher.DECRYPT_MODE, privfinal);
            byte[] decryptedData = cipherDecrypt.doFinal(inputCipherBytes);
            System.out.println("Decrpy" + arr(decryptedData));

            System.out.println(pubfinal.getPublicExponent());
            byte[] modulus = pubfinal.getModulus().toByteArray();
            byte[] exponent = pubfinal.getPublicExponent().toByteArray();

            System.out.println("Modulus " + arr(modulus));
            System.out.println("Exponent " + arr(exponent));
            System.out.println("Plain Text" + arr(byteArray));

            Cipher encryptCipher = Cipher.getInstance("RSA");
            Cipher encryptCipher2 = Cipher.getInstance("RSA/ECB/OAEPWITHSHA1ANDMGF1PADDING");
            encryptCipher.init(Cipher.ENCRYPT_MODE, pubfinal);
            encryptCipher2.init(Cipher.ENCRYPT_MODE, pubfinal);

            Cipher cipherDecrypt2 = Cipher.getInstance("RSA/ECB/OAEPWITHSHA1ANDMGF1PADDING");


            byte[] encryptedMessageBytes = encryptCipher.doFinal(byteArray);
            System.out.println("Encrypted Text" + arr(encryptedMessageBytes));
            byte[] encryptedMessageBytes2 = encryptCipher2.doFinal(byteArray);
            System.out.println("Encrypted Text SHA1" + arr(encryptedMessageBytes2));
            cipherDecrypt2.init(Cipher.DECRYPT_MODE, privfinal);
            byte[] decryptedData2 = cipherDecrypt.doFinal(encryptedMessageBytes2);
            System.out.println("Decrypted encrypted" + arr(decryptedData2));


        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }

    }


}