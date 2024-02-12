package com.cb.base64;

import com.cb.util.CbConstants;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptedToken {

    private static SecretKey KEY = null;
    private static IvParameterSpec IV_PARAMETER_SPEC = null;
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";


    public static String getEncryptedToken(String data) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        var plainToken = Base64.getEncoder().encodeToString(data.getBytes());
        if (KEY == null)
            KEY = generateKey();
        if (IV_PARAMETER_SPEC == null)
            IV_PARAMETER_SPEC = generateIv();
        return encrypt(ALGORITHM, plainToken, KEY, IV_PARAMETER_SPEC);
    }

    public static String getDecryptedData(String token) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        var encryptedData = decrypt(ALGORITHM, token, KEY, IV_PARAMETER_SPEC);
        return new String(Base64.getDecoder().decode(encryptedData));
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        System.out.println("Creating encrypted token ...");
        var token = getEncryptedToken(CbConstants.DATA);
        System.out.println("Encrypted Token: " + token);
        System.out.println("Parsing token ...");
        var data = getDecryptedData(token);
        System.out.println("Date: " + data);
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String algorithm, String input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }
}
