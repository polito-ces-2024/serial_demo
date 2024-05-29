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
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
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
        String privKey = new String(Main.class.getClassLoader().getResourceAsStream("public-key.pem").readAllBytes());
        System.out.println(privKey);
        byte[] byteArray = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        String sanitizedPub = pubkey.
                replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(sanitizedPub);
        System.out.println("Public key is " + encoded.length + " bytes");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        RSAPublicKey pubfinal = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        System.out.println(pubfinal.getPublicExponent());
            byte[] modulus = pubfinal.getModulus().toByteArray();
            byte[] exponent = pubfinal.getPublicExponent().toByteArray();

            System.out.println("Modulus " + arr(modulus));
            System.out.println("Exponent " + arr(exponent));
            System.out.println("Plain Text" + arr(byteArray));

            Cipher encryptCipher = Cipher.getInstance("RSA");
            Cipher encryptCipher2 = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, pubfinal);
            encryptCipher2.init(Cipher.ENCRYPT_MODE, pubfinal);

            byte[] encryptedMessageBytes = encryptCipher.doFinal(byteArray);
            System.out.println("Encrypted Text" + arr(encryptedMessageBytes));
            byte[] encryptedMessageBytes2 = encryptCipher2.doFinal(byteArray);
            System.out.println("Encrypted Text SHA1" + arr(encryptedMessageBytes2));

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