package eu.krausrichard.pqchat.crypt.impl;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;

import eu.krausrichard.pqchat.crypt.api.KeyExchange;

import java.security.SecureRandom;

public class KyberKeyExchange implements KeyExchange {
    
    private static final KyberParameters PARAMS = KyberParameters.kyber768;

    private final SecureRandom random = new SecureRandom();

    private KyberPrivateKeyParameters privateKey;
    private KyberPublicKeyParameters publicKey;

    @Override
    public void generateKeyPair(){
        
        KyberKeyPairGenerator kpGen = new KyberKeyPairGenerator();
        kpGen.init(new KyberKeyGenerationParameters(random, PARAMS));

        org.bouncycastle.crypto.AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        this.privateKey = (KyberPrivateKeyParameters) kp.getPrivate();
        this.publicKey = (KyberPublicKeyParameters) kp.getPublic();
    }

    @Override
    public byte[] getPublicKey(){
        if (publicKey == null) throw new IllegalStateException("Key doesn't exist!");

        return publicKey.getEncoded();
    }

    @Override
    public byte[][] encapsulateSecret(byte[] otherPublicKeyBytes){

        KyberPublicKeyParameters otherPublicKey = new KyberPublicKeyParameters(PARAMS, otherPublicKeyBytes);

        KyberKEMGenerator kemGen = new KyberKEMGenerator(random);

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(otherPublicKey);

        return new byte[][] {secEnc.getEncapsulation(), secEnc.getSecret()};
    }

    @Override
    public byte[] decapsulateSecret(byte[] capsule) {
        if (privateKey == null) throw new IllegalStateException("No private key to decapsulate!");

        KyberKEMExtractor kemExt = new KyberKEMExtractor(privateKey);
        return kemExt.extractSecret(capsule);
    }

}
