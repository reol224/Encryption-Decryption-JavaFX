package com.jul.encryptingfiles;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Logger;

public class EncodeDecode {
    private static Logger log = Logger.getLogger(EncodeDecode.class.getName());

    static String data = "";

    public static String readFile(File file) {
        try {
            byte[] fileBytes = Files.readAllBytes(file.toPath());
            data = new String(fileBytes);
            return data;
        } catch (IOException e) {
            log.warning("Failed to read file: " + file.getAbsolutePath());
            e.printStackTrace();
        }
        return null;
    }

    public static SecretKey generateKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize, new SecureRandom());
        return keyGenerator.generateKey();
    }

    public static SecretKey getKeyFromPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16]; // 16 bytes for AES
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(algorithm);

            if (input != null) {
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                byte[] cipherText = cipher.doFinal(input.getBytes());

                byte[] ivBytes = (iv != null) ? iv.getIV() : new byte[0];

                // Combine the IV and ciphertext for later decryption
                byte[] encryptedData = new byte[ivBytes.length + cipherText.length];
                System.arraycopy(ivBytes, 0, encryptedData, 0, ivBytes.length);
                System.arraycopy(cipherText, 0, encryptedData, ivBytes.length, cipherText.length);

                return Base64.getEncoder().encodeToString(encryptedData);
            } else {
                log.warning("Encryption failed. Input data is null.");
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            log.warning("Failed to encrypt data");
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(algorithm);

            byte[] encryptedData = Base64.getDecoder().decode(cipherText);
            byte[] ivBytes = new byte[16];
            System.arraycopy(encryptedData, 0, ivBytes, 0, ivBytes.length);
            byte[] cipherTextBytes = new byte[encryptedData.length - ivBytes.length];
            System.arraycopy(encryptedData, ivBytes.length, cipherTextBytes, 0, cipherTextBytes.length);

            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
            byte[] plainText = cipher.doFinal(cipherTextBytes);

            return new String(plainText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            log.warning("Failed to decrypt data");
            e.printStackTrace();
        }
        return null;
    }
}
