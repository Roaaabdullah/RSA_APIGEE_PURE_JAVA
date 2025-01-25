package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import com.google.apigee.encoding.Base16;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;

public class RsaCrypto extends RsaBase implements Execution {
  private static final String defaultCipherName = "RSA";
  private static final String defaultCryptoMode = "ECB"; // alias: None. RSA/ECB/PKCS1Padding actually uses no ECB
  private static final String defaultCryptoPadding = "PKCS1Padding";
  private static final Pattern paddingPattern = Pattern.compile(
      "^(PKCS1|OAEP|PKCS1Padding|OAEPWithSHA-256AndMGF1Padding)$", Pattern.CASE_INSENSITIVE);
  private static final Pattern fullCipherPattern = Pattern.compile(
      "^(RSA)/(None|ECB)/(PKCS1Padding|OAEPWithSHA-256AndMGF1Padding)$",
      Pattern.CASE_INSENSITIVE);
  private static final Pattern cipherNamePattern = Pattern.compile("^(RSA)$", Pattern.CASE_INSENSITIVE);
  private static final Pattern modeNamePattern = Pattern.compile("^(None|ECB)$", Pattern.CASE_INSENSITIVE);

  public RsaCrypto(Map properties) {
    super(properties);
  }

  enum CryptoAction {
    DECRYPT,
    ENCRYPT
  };

  String getVarPrefix() {
    return "crypto_";
  }

  private EncodingType _getEncodingTypeProperty(MessageContext msgCtxt, String propName)
      throws Exception {
    return EncodingType.valueOf(_getStringProp(msgCtxt, propName, "NONE").toUpperCase());
  }

  private EncodingType getEncodeResult(MessageContext msgCtxt) throws Exception {
    return _getEncodingTypeProperty(msgCtxt, "encode-result");
  }

  private static CryptoAction findByName(String name) {
    for (CryptoAction action : CryptoAction.values()) {
      if (name.equals(action.name())) {
        return action;
      }
    }
    return null;
  }

  private CryptoAction getAction(MessageContext msgCtxt) throws Exception {
    String action = this.properties.get("action");
    if (action != null)
      action = action.trim();
    if (action == null || action.equals("")) {
      throw new IllegalStateException("specify an action.");
    }
    action = resolveVariableReferences(action, msgCtxt);

    CryptoAction cryptoAction = findByName(action.toUpperCase());
    if (cryptoAction == null)
      throw new IllegalStateException("specify a valid action.");

    return cryptoAction;
  }

  private String getPadding(MessageContext msgCtxt) throws Exception {
    String padding = _getStringProp(msgCtxt, "padding", defaultCryptoPadding);
    Matcher m = paddingPattern.matcher(padding);
    if (!m.matches()) {
      throw new IllegalStateException(String.format("Supplied padding (%s) is invalid.", padding));
    }
    if ("OAEP".equals(padding)) {
      padding = "OAEPWithSHA-256AndMGF1Padding"; // alias
    } else if ("PKCS1".equals(padding)) {
      padding = "PKCS1Padding"; // alias
    }
    return padding;
  }

  private String getMode(MessageContext msgCtxt) throws Exception {
    return _getStringProp(msgCtxt, "mode", defaultCryptoMode);
  }

  private String getCipherName(MessageContext msgCtxt) throws Exception {
    String cipher = (String) this.properties.get("cipher");
    if (cipher == null || cipher.equals("")) {
      return defaultCipherName + "/" + getMode(msgCtxt) + "/" + getPadding(msgCtxt);
    }
    cipher = resolveVariableReferences(cipher, msgCtxt);
    if (cipher == null || cipher.equals("")) {
      throw new IllegalStateException("cipher resolves to null or empty.");
    }
    Matcher m = fullCipherPattern.matcher(cipher);
    if (m.matches()) {
      return cipher;
    }

    m = cipherNamePattern.matcher(cipher);
    if (!m.matches()) {
      throw new IllegalStateException("that cipher name is unsupported.");
    }

    // it is a simple algorithm name; apply mode and padding
    cipher += "/" + getMode(msgCtxt) + "/" + getPadding(msgCtxt);
    m = fullCipherPattern.matcher(cipher);
    if (!m.matches()) {
      throw new IllegalStateException("that cipher is unsupported.");
    }
    return cipher;
  }

  private boolean getUtf8DecodeResult(MessageContext msgCtxt) throws Exception {
    return _getBooleanProperty(msgCtxt, "utf8-decode-result", false);
  }

  private void clearVariables(MessageContext msgCtxt) {
    msgCtxt.removeVariable(varName("error"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
    msgCtxt.removeVariable(varName("action"));
  }

  private void setOutput(MessageContext msgCtxt, CryptoAction action, byte[] source, byte[] result)
      throws Exception {
    EncodingType outputEncodingWanted = getEncodeResult(msgCtxt);
    String outputVar = getOutputVar(msgCtxt);
    boolean emitGeneratedKey = (action == CryptoAction.ENCRYPT) && _getBooleanProperty(msgCtxt, "generate-key", false);

    Function<byte[], Object> encoder = null;
    if (outputEncodingWanted == EncodingType.NONE) {
      // Emit the result as a Java byte array.
      // Will be retrievable only by another Java callout.
      msgCtxt.setVariable(varName("output_encoding"), "none");
      encoder = (a) -> a; // nop
    } else if (outputEncodingWanted == EncodingType.BASE64) {
      msgCtxt.setVariable(varName("output_encoding"), "base64");
      encoder = (a) -> Base64.getEncoder().encodeToString(a);
    } else if (outputEncodingWanted == EncodingType.BASE64URL) {
      msgCtxt.setVariable(varName("output_encoding"), "base64url");
      encoder = (a) -> Base64.getUrlEncoder().encodeToString(a);
    } else if (outputEncodingWanted == EncodingType.BASE16) {
      msgCtxt.setVariable(varName("output_encoding"), "base16");
      // encoder = (a) -> Base16.encode(a);
    } else {
      throw new IllegalStateException("unhandled encoding");
    }

    msgCtxt.setVariable(outputVar, encoder.apply(result));
    if (emitGeneratedKey) {
      String outputKeyVar = varName("output_key");
      msgCtxt.setVariable(outputKeyVar, encoder.apply(source));
    }
  }

  protected byte[] getSourceBytes(CryptoAction action, MessageContext msgCtxt) throws Exception {
    if (action == CryptoAction.ENCRYPT) {
      boolean wantGenerateKey = _getBooleanProperty(msgCtxt, "generate-key", false);
      if (wantGenerateKey) {
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        return key;
      }
    }

    Object source1 = msgCtxt.getVariable(getSourceVar());
    if (source1 instanceof byte[]) {
      return (byte[]) source1;
    }

    if (source1 instanceof String) {
      try {
        EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-source");
        return decodeString((String) source1, decodingKind);
        // return (source1.toString()).getBytes(StandardCharsets.UTF_8);
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException("Invalid Base64 input string", e);
      }
    }

    // coerce and hope for the best
    return (source1.toString()).getBytes(StandardCharsets.UTF_8);
  }

  // Encrypt data using RSA public key
  public static byte[] encrypt(String data, PublicKey publicKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher.doFinal(data.getBytes("UTF-8"));
  }

  // Decrypt data using RSA private key
  public static String decrypt(byte[] data, PrivateKey privateKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return new String(cipher.doFinal(data), "UTF-8");

  }

  // Convert PEM string to PublicKey object
  public static PublicKey getPublicKeyFromPEM(String pem) throws Exception {
    pem = pem.replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s+", ""); // Remove all whitespace
    byte[] keyBytes = Base64.getDecoder().decode(pem);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePublic(spec);
  }

  // Convert PEM string to PrivateKey object
  public static PrivateKey getPrivateKeyFromPEM(String pem) throws Exception {
    pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replaceAll("\\s+", ""); // Remove all whitespace
    byte[] keyBytes = Base64.getDecoder().decode(pem);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePrivate(spec);
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = false;
    try {
      clearVariables(msgCtxt);
      debug = getDebug(msgCtxt);
      String cipherName = getCipherName(msgCtxt);
      msgCtxt.setVariable(varName("cipher"), cipherName);

      CryptoAction action = getAction(msgCtxt); // encrypt or decrypt
      msgCtxt.setVariable(varName("action"), action.name());
      msgCtxt.setVariable(varName("custom_java"), "new keys uu!");

      if (action == CryptoAction.DECRYPT) {
        byte[] source1 = getSourceBytes(action, msgCtxt);
        String privateKeyString = _getStringProp(msgCtxt, "private-key", null);
        PrivateKey privateKey = getPrivateKeyFromPEM(privateKeyString);

        String decryptData = decrypt(source1, privateKey);

        if (getUtf8DecodeResult(msgCtxt)) {
          msgCtxt.setVariable(getOutputVar(msgCtxt), decryptData);
        } else {
          // setOutput(msgCtxt, action, source, encryptedData);
          // private void setOutput(MessageContext msgCtxt, CryptoAction action, byte[]
          // ource, byte[] result)

        }
      } else {
        String publicKeyString = _getStringProp(msgCtxt, "public-key", null);
        String source2 = new String(getSourceBytes(action, msgCtxt), StandardCharsets.UTF_8);
        PublicKey publicKeyFromString = getPublicKeyFromPEM(publicKeyString);

        byte[] encryptData = encrypt(source2, publicKeyFromString);

        msgCtxt.setVariable(getOutputVar(msgCtxt), Base64.getUrlEncoder().encodeToString(encryptData));
        // setOutput(msgCtxt, action, source, decryptedData);
      }
    } catch (Exception e) {
      if (debug) {
        e.printStackTrace();
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }

}
