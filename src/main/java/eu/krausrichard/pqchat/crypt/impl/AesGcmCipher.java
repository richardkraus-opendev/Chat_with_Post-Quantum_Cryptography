package eu.krausrichard.pqchat.crypt.impl;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import eu.krausrichard.pqchat.crypt.api.SymmetricCipher;

import java.security.SecureRandom;
import java.nio.ByteBuffer;

public class AesGcmCipher implements SymmetricCipher {
    
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int NONCE_LENGTH_BYTE = 12;

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public byte[] encrypt(byte[] data, byte[] key)
    {
        try{
            
            byte[] nonce = new byte[NONCE_LENGTH_BYTE];
            secureRandom.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);

            byte[] cipherText = cipher.doFinal(data);

            return ByteBuffer.allocate(nonce.length + cipherText.length)
                .put(nonce)
                .put(cipherText)
                .array();

        } catch(Exception e){
            throw new RuntimeException("Encryption error " + e.getMessage());
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedDataWithNonce, byte[] key)
    {
        try{

            ByteBuffer bb = ByteBuffer.wrap(encryptedDataWithNonce);
            byte[] nonce = new byte[NONCE_LENGTH_BYTE];
            bb.get(nonce);
            byte[] cipherText = new byte[bb.remaining()];
            bb.get(cipherText);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, nonce);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);

            return cipher.doFinal(cipherText);
        } catch(Exception e){
            throw new RuntimeException("Decryption failed " + e.getMessage());
        }
    }
}
