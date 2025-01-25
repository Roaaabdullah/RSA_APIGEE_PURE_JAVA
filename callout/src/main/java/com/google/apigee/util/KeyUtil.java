package com.google.apigee.util;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyUtil {

  private KeyUtil() {
  }

  private static String reformIndents(String s) {
    return s.trim().replaceAll("([\\r|\\n] +)", "\n");
  }

  public static PublicKey decodePublicKey(String publicKeyString) throws Exception {
    publicKeyString = reformIndents(publicKeyString);
    publicKeyString = publicKeyString.replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s", "");
    byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePublic(spec);
  }

  public static RSAPrivateKey decodePrivateKey(String privateKeyPemString, String password) throws Exception {
    if (privateKeyPemString == null) {
      throw new IllegalStateException("PEM String is null");
    }
    privateKeyPemString = reformIndents(privateKeyPemString);
    privateKeyPemString = privateKeyPemString.replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replaceAll("\\s", "");
    byte[] keyBytes = Base64.getDecoder().decode(privateKeyPemString);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return (RSAPrivateKey) keyFactory.generatePrivate(spec);
  }

  public static SecretKey generateAESKey(int keySize) throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(keySize);
    return keyGen.generateKey();
  }

  public static byte[] encryptAESKeyWithRSA(PublicKey publicKey, SecretKey aesKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher.doFinal(aesKey.getEncoded());
  }

  public static SecretKey decryptAESKeyWithRSA(PrivateKey privateKey, byte[] encryptedAESKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] decryptedKey = cipher.doFinal(encryptedAESKey);
    return new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
  }

  public static byte[] encryptDataWithAES(SecretKey aesKey, byte[] data) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, aesKey);
    return cipher.doFinal(data);
  }

  public static byte[] decryptDataWithAES(SecretKey aesKey, byte[] encryptedData) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.DECRYPT_MODE, aesKey);
    return cipher.doFinal(encryptedData);
  }
}
