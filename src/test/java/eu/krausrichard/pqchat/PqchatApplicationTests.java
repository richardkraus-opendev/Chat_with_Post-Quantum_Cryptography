package eu.krausrichard.pqchat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import eu.krausrichard.pqchat.crypt.impl.AesGcmCipher;
import eu.krausrichard.pqchat.crypt.impl.KyberKeyExchange;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class PqchatApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void testKyberKeyExchange(){

		KyberKeyExchange firstKem = new KyberKeyExchange();
		KyberKeyExchange secundKem = new KyberKeyExchange();

		firstKem.generateKeyPair();
		byte[] firstPublicKey = firstKem.getPublicKey();

		byte[][] secundResult = secundKem.encapsulateSecret(firstPublicKey);
		byte[] capsuleToProcess = secundResult[0];
		byte[] secundSecret = secundResult[1];

		byte[] firstSecret = firstKem.decapsulateSecret(capsuleToProcess);

		//Verification
		assertNotNull(firstSecret, "first secret is null!");
		assertNotNull(secundSecret, "secund secret is null!");

		boolean isMatch = Arrays.equals(firstSecret, secundSecret);
		assertTrue(isMatch, "Secrets are not identical!");
	}

	@Test
	void testAesGcmEncryptionDecryption(){

		AesGcmCipher cipher = new AesGcmCipher();

		byte[] dummyAesKey = new byte[32];
		new SecureRandom().nextBytes(dummyAesKey);

		String originalMessage = "Lorem ipsum dolor sit amet consectetur adipiscing elit. Dolor sit amet consectetur adipiscing elit quisque faucibus.";
		byte[] messageBytes = originalMessage.getBytes(StandardCharsets.UTF_8);

		byte[] encryptedData = cipher.encrypt(messageBytes, dummyAesKey);

		byte[] decryptedData = cipher.decrypt(encryptedData, dummyAesKey);

		String finalMessage = new String(decryptedData, StandardCharsets.UTF_8);

		//Verification
		assertNotNull(encryptedData, "Encrypted Data are null!");

		assertEquals(originalMessage, finalMessage, "Decrypted message does NOT match the original!");
	}
}
