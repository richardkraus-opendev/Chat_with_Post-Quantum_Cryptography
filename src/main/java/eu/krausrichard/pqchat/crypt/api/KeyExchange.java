package eu.krausrichard.pqchat.crypt.api;

public interface KeyExchange {
    
    void generateKeyPair();

    byte[] getPublicKey();

    byte[][] encapsulateSecret(byte[] otherPublicKey);

    byte[] decapsulateSecret(byte[] capsule);

}