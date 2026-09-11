package com.example;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;

/** JCA calls whose verdicts differ: broken, deprecated, current, post-quantum. Not a real service. */
public final class LegacyAndPqc {
    public static void main(String[] args) throws Exception {
        Cipher ecb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        Cipher tripleDes = Cipher.getInstance("DESede/CBC/PKCS5Padding");

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(1024);
        rsa.generateKeyPair();

        KeyPairGenerator ed = KeyPairGenerator.getInstance("Ed25519");
        ed.generateKeyPair();

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        ec.generateKeyPair();

        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
        dsa.initialize(2048);
        dsa.generateKeyPair();

        // Java 24 names (JEP 496, JEP 497).
        KeyPairGenerator mlKem = KeyPairGenerator.getInstance("ML-KEM");
        mlKem.generateKeyPair();
        KeyPairGenerator mlDsa = KeyPairGenerator.getInstance("ML-DSA");
        mlDsa.generateKeyPair();
    }
}
