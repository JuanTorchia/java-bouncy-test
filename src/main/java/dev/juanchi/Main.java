package dev.juanchi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Crear la Autoridad Certificadora (CA)
        CertificateAuthority ca = new CertificateAuthority();

        // Generar pares de claves para Alice y Bob
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGen.initialize(2048);

        KeyPair aliceKeyPair = keyPairGen.generateKeyPair();
        KeyPair bobKeyPair = keyPairGen.generateKeyPair();

        // Generar certificados para Alice y Bob firmados por la CA
        X509Certificate aliceCert = ca.generateSignedCertificate("Alice", aliceKeyPair.getPublic());
        X509Certificate bobCert = ca.generateSignedCertificate("Bob", bobKeyPair.getPublic());

        // Crear instancias de EncryptedChat para Alice y Bob
        EncryptedChat aliceChat = new EncryptedChat(aliceKeyPair.getPrivate(), bobCert);
        EncryptedChat bobChat = new EncryptedChat(bobKeyPair.getPrivate(), aliceCert);

        // Alice envía la clave AES cifrada a Bob
        String encryptedAESKeyAndIv = aliceChat.exchangeAESKey();
        bobChat.receiveAESKey(encryptedAESKeyAndIv);

        // Comunicación cifrada
        String messageFromAlice = "Hola, Bob! Este es un mensaje seguro.";
        System.out.println("Alice envía: " + messageFromAlice);
        String encryptedMessage = aliceChat.encryptMessage(messageFromAlice);

        // Bob recibe y descifra el mensaje
        String decryptedMessage = bobChat.decryptMessage(encryptedMessage);
        System.out.println("Bob recibe: " + decryptedMessage);

        // Bob responde
        String messageFromBob = "Hola, Alice! Mensaje recibido de forma segura.";
        System.out.println("Bob envía: " + messageFromBob);
        String encryptedResponse = bobChat.encryptMessage(messageFromBob);

        // Alice recibe y descifra la respuesta
        String decryptedResponse = aliceChat.decryptMessage(encryptedResponse);
        System.out.println("Alice recibe: " + decryptedResponse);
    }
}
