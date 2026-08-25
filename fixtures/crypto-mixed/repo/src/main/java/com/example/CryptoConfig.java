package com.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.net.ssl.SSLContext;

public class CryptoConfig {
    public void configureTls() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
    }

    public void generateRsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kpg.generateKeyPair();
    }

    public void encryptWithAes() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    public void hashWithSha256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
    }
}
