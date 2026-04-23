package eu.krausrichard.pqchat.crypt.api;

public interface SymmetricCipher {
    
    byte[] encrypt(byte[] data, byte[] key);

    byte[] decrypt(byte[] encryptedData, byte[] key);

}
 