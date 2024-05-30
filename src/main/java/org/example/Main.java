package org.example;
import com.fazecast.jSerialComm.SerialPort;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;

public class Main {
    final protected static char[] hexArray = "0123456789abcdef".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


    public static String arr(byte[] m) {

        StringBuilder sb = new StringBuilder();
        for (byte b : m) {
            sb.append(String.format("0x%02X, ", b));
        }
        return "[" + sb.toString() + "] length:" + m.length;
    }



    public static PrivateKey readPrivateKeyFromPemString(String pemString) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemString))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            Object object = pemParser.readObject();
            if (object instanceof PEMKeyPair) {
                PEMKeyPair keyPair = (PEMKeyPair) object;
                // Extract the private key from the key pair
                return converter.getPrivateKey(keyPair.getPrivateKeyInfo());
            }
            throw new IllegalArgumentException("No private key found in PEM string: " + pemString);
        }
    }
    public static KeyPair readFull(String pemString) throws  Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Reader rdr = new StringReader (pemString);
        Object parsed = new org.bouncycastle.openssl.PEMParser(rdr).readObject();
        KeyPair pair = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().getKeyPair((org.bouncycastle.openssl.PEMKeyPair)parsed);
        System.out.println (pair.getPrivate().getAlgorithm());
        return pair;
    }
    public static PublicKey readPublicKeyFromPemString(String pemString) throws IOException {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemString))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            Object object = pemParser.readObject();
            if (object instanceof SubjectPublicKeyInfo) {
                SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) object;
                return converter.getPublicKey(publicKeyInfo);
            }
            throw new IllegalArgumentException("Invalid PEM string: " + pemString);
        }
    }

    public static byte [] savePrivateKey (PrivateKey key) throws Exception
    {
        //return key.getEncoded();

        ECPrivateKey eckey = (ECPrivateKey)key;
        return eckey.getD().toByteArray();
    }
    public static PrivateKey loadPrivateKey (byte [] data) throws Exception
    {
        //KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        //return kf.generatePrivate(new PKCS8EncodedKeySpec(data));

        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime256v1");
        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return kf.generatePrivate(prvkey);
    }
    public static PublicKey loadPublicKey (byte [] data) throws Exception
    {
		/*KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(new X509EncodedKeySpec(data));*/

        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime256v1");
        ECPublicKeySpec pubKey = new ECPublicKeySpec(
                params.getCurve().decodePoint(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return kf.generatePublic(pubKey);
    }
    public static byte [] savePublicKey (PublicKey key) throws Exception
    {
        //return key.getEncoded();

        ECPublicKey eckey = (ECPublicKey)key;
        return eckey.getQ().getEncoded(false);
    }
    public static void doECDH (String name, byte[] dataPrv, byte[] dataPub) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(loadPrivateKey(dataPrv));
        ka.doPhase(loadPublicKey(dataPub), true);
        byte [] secret = ka.generateSecret();
        System.out.println(name + bytesToHex(secret));
    }
    public static void main(String[] args) {
        //System.out.println(HardwareDetector.detectHardware());
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String pubkeyDevice = new String(Main.class.getClassLoader().getResourceAsStream("public_key_ecc_device.pem").readAllBytes());
        System.out.println(pubkeyDevice);
        String privKeyDevice = new String(Main.class.getClassLoader().getResourceAsStream("private_key_ecc_device.pem").readAllBytes());
        System.out.println(privKeyDevice);

        String pubkeyPc = new String(Main.class.getClassLoader().getResourceAsStream("public_key_ecc.pem").readAllBytes());
        System.out.println(pubkeyDevice);
        String privKeyPc = new String(Main.class.getClassLoader().getResourceAsStream("private_key_ecc.pem").readAllBytes());
        System.out.println(privKeyDevice);

        PrivateKey devicePriv = readPrivateKeyFromPemString(privKeyDevice);

        KeyPair demo = readFull(privKeyDevice);
        System.out.println("Keypair " + demo.getPrivate());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECPrivateKey pk = (ECPrivateKey) keyPair.getPrivate();
            System.out.println("pk: " + pk);
        PublicKey devicePublic = readPublicKeyFromPemString(pubkeyDevice);
        KeyPair pairDevice = new KeyPair(devicePublic, devicePriv);

        PrivateKey pcPriv = readPrivateKeyFromPemString(privKeyPc);

        PublicKey pcPublic = readPublicKeyFromPemString(pubkeyPc);

        KeyPair pairPc = new KeyPair(pcPublic, pcPriv);

        System.out.println("Pc " + pairPc.getPrivate());
        System.out.println("Pc " + pairPc.getPublic());

        System.out.println("Private key bytes of device (ignore first)" +  arr(savePrivateKey(pairDevice.getPrivate())));
        System.out.println("Public key bytes of device (ignore first)" +  arr(savePublicKey(pairDevice.getPublic())));

            System.out.println("Private key bytes of PC (ignore first)" +  arr(savePrivateKey(pairPc.getPrivate())));
            System.out.println("Public key bytes of PC (ignore first)" +  arr(savePublicKey(pairPc.getPublic())));



            //System.out.println("Device " + pairDevice.getPrivate());
   // System.out.println("Device " + pairDevice.getPublic());


            byte [] dataPrvA = savePrivateKey(pairDevice.getPrivate());
            byte [] dataPubA = savePublicKey(pairDevice.getPublic());
            byte [] dataPrvB = savePrivateKey(pairDevice.getPrivate());
            byte [] dataPubB = savePublicKey(pairDevice.getPublic());



            doECDH("PC's secret: ", dataPrvA, dataPubB);
            doECDH("Device's secret:   ", dataPrvB, dataPubA);
            //ECKey privEC = (ECKey) PemUtils.readPrivateKeyFromFile("/home/riccardo/IdeaProjects/serial_demo/src/main/resources/private_key_ecc.pem", "EC");
           // System.out.println(privEC.toString());
           // System.out.println(privEC.getParameters());
/*
            System.out.println("Device public " + arr(devicePublic.getEncoded()) + " length " + devicePublic.getEncoded().length);
        System.out.println("Device priv " + arr(devicePriv.getEncoded()) + "length " + devicePriv.getEncoded().length);
        System.out.println("PC public " + arr(pcPublic.getEncoded()) + " length " + pcPublic.getEncoded().length);
        System.out.println("PC priv " + arr(pcPriv.getEncoded()) + "length " + pcPriv.getEncoded().length);

 */
/*
            String sanitizedPub = pubkey.
                replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");
            System.out.println("RAW PUB: " +  sanitizedPub);

            String sanitizedPriv = privKey.
                    replace("-----BEGIN EC PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END EC PRIVATE KEY-----", "");
            System.out.println("Raw priv: " + sanitizedPriv);

            byte[] rawPriv = Base64.getDecoder().decode(sanitizedPriv);

        byte[] rawPublic = Base64.getDecoder().decode(sanitizedPub);
        System.out.println("Private key is " + rawPriv.length + " bytes");

        System.out.println("Bytes of public " + arr(rawPublic));
            System.out.println("Bytes of private " + arr(rawPriv));



*/
        //KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        /*
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


         */
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }


}