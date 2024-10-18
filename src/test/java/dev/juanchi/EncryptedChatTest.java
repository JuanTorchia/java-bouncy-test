package dev.juanchi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class EncryptedChatTest {

    private CertificateAuthority ca;
    private EncryptedChat aliceChat;
    private EncryptedChat bobChat;

    @BeforeEach
    void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        ca = new CertificateAuthority();
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGen.initialize(2048);

        KeyPair aliceKeyPair = keyPairGen.generateKeyPair();
        KeyPair bobKeyPair = keyPairGen.generateKeyPair();

        X509Certificate aliceCert = ca.generateSignedCertificate("Alice", aliceKeyPair.getPublic());
        X509Certificate bobCert = ca.generateSignedCertificate("Bob", bobKeyPair.getPublic());

        aliceChat = new EncryptedChat(aliceKeyPair.getPrivate(), bobCert);
        bobChat = new EncryptedChat(bobKeyPair.getPrivate(), aliceCert);

        // Intercambio de claves AES
        String encryptedAESKeyAndIv = aliceChat.exchangeAESKey();
        bobChat.receiveAESKey(encryptedAESKeyAndIv);
    }

    @Test
    void testBasicEncryptionDecryption() throws Exception {
        String message = "Hola, Bob!";
        String encrypted = aliceChat.encryptMessage(message);
        String decrypted = bobChat.decryptMessage(encrypted);

        assertEquals(message, decrypted);
    }

    @Test
    void testEmptyMessage() throws Exception {
        String message = "";
        String encrypted = aliceChat.encryptMessage(message);
        String decrypted = bobChat.decryptMessage(encrypted);

        assertEquals(message, decrypted);
    }

    @Test
    void testLongMessage() throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append("Mensaje largo ");
        }
        String message = sb.toString();

        String encrypted = aliceChat.encryptMessage(message);
        String decrypted = bobChat.decryptMessage(encrypted);

        assertEquals(message, decrypted);
    }

    @Test
    void testTamperedMessage() throws Exception {
        String message = "Mensaje original";
        String encrypted = aliceChat.encryptMessage(message);
        // Alteramos el mensaje cifrado
        encrypted = encrypted.substring(0, encrypted.length() - 1) + "X";

        String finalEncrypted = encrypted;
        assertThrows(Exception.class, () -> bobChat.decryptMessage(finalEncrypted));
    }

    @Test
    void testAESKeyNotExchanged() throws Exception {
        EncryptedChat chatWithoutKey = new EncryptedChat(aliceChat.privateKey, bobChat.getPartnerCertificate());

        assertThrows(IllegalStateException.class, () -> chatWithoutKey.encryptMessage("Hola"));
    }
}
