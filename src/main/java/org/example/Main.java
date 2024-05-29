package org.example;
import com.fazecast.jSerialComm.SerialPort;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
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
    public static void main(String[] args) {
        //System.out.println(HardwareDetector.detectHardware());
        try {

        String pubkey = new String(Main.class.getClassLoader().getResourceAsStream("public-key.pem").readAllBytes());
        System.out.println(pubkey);
        String privKey = new String(Main.class.getClassLoader().getResourceAsStream("public-key.pem").readAllBytes());
        System.out.println(privKey);

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
        System.out.println(pubfinal.getModulus());
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

    }


}