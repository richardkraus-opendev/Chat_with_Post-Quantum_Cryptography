package crypto.symmetric;

public abstract class SymetricCipher {
    
    public abstract byte[] encrypt(byte[] key, byte[] plaintext);

    public abstract byte[] decrypt(byte[] key, byte[] ciphertext);

}
