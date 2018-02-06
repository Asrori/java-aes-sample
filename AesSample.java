package aes.sample;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AesSample {
    
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;
    
    public static byte[] encrypt(byte[] data, String passHash, byte[] key, byte[] ivs) {
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(passHash.toCharArray(), key, 1000, 384);
        Key secretKey = factory.generateSecret(pbeKeySpec);
        byte[] key1 = new byte[32];
        System.arraycopy(secretKey.getEncoded(), 0, key1, 0, 32);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key1, "AES");
        byte[] finalIvs = new byte[16];
        int len = ivs.length > 16 ? 16 : ivs.length;
        System.arraycopy(ivs, 0, finalIvs, 0, len);
        IvParameterSpec ivps = new IvParameterSpec(finalIvs);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivps);
        return cipher.doFinal(data);
    } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
        e.printStackTrace();
    }

    return null;
}

public static byte[] decrypt(byte[] data, String passHash, byte[] key, byte[] ivs) {
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(passHash.toCharArray(), key, 1000, 384);
        Key secretKey = factory.generateSecret(pbeKeySpec);
        byte[] key1 = new byte[32];
        System.arraycopy(secretKey.getEncoded(), 0, key1, 0, 32);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key1, "AES");
        byte[] finalIvs = new byte[16];
        int len = ivs.length > 16 ? 16 : ivs.length;
        System.arraycopy(ivs, 0, finalIvs, 0, len);
        IvParameterSpec ivps = new IvParameterSpec(finalIvs);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivps);
        return cipher.doFinal(data);
    } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
        e.printStackTrace();
    }

    return null;
}
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // Add padding zero manually using \0
        String dataToEncryptDecrypt = "password\0\0\0\0\0\0\0\0";
        
        String passwordHash = "P@@Sw0rd";
        String encryptionDecryptionKey = "S@LTKEY!";
        String ivs = "@1B2c3D4e5F6g7H8";

        byte[] encryptedData = encrypt(dataToEncryptDecrypt.getBytes(), passwordHash, encryptionDecryptionKey.getBytes(), ivs.getBytes());
        System.out.println("encrypted string : " + Base64.getEncoder().encodeToString(encryptedData));
        // here you will get the encrypted bytes. Now you can use Base64 encoding on these bytes, before sending to your web-service
        
        byte[] decryptedData = decrypt(encryptedData, passwordHash, encryptionDecryptionKey.getBytes(), ivs.getBytes());
        System.out.println(new String(decryptedData));
    }
    
}
