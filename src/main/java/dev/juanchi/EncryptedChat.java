package dev.juanchi;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class EncryptedChat {
    final PrivateKey privateKey;
    private final PublicKey partnerPublicKey;
    private final X509Certificate partnerCertificate;
    private SecretKey aesKey;
    private IvParameterSpec ivParameterSpec;

    public EncryptedChat(PrivateKey privateKey, X509Certificate partnerCertificate) throws Exception {
        this.privateKey = privateKey;
        this.partnerCertificate = partnerCertificate;
        this.partnerPublicKey = partnerCertificate.getPublicKey();
    }

    public String exchangeAESKey() throws Exception {
        // Generar clave AES de 256 bits
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        this.aesKey = keyGen.generateKey();

        // Generar IV aleatorio de 16 bytes para AES CBC
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        this.ivParameterSpec = new IvParameterSpec(iv);

        // Cifrar la clave AES con la clave pública del compañero (RSA)
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        rsaCipher.init(Cipher.ENCRYPT_MODE, partnerPublicKey);
        byte[] encryptedAESKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Codificar en Base64 para envío
        String encryptedKeyBase64 = Base64.getEncoder().encodeToString(encryptedAESKey);
        String ivBase64 = Base64.getEncoder().encodeToString(iv);

        // Enviar la clave cifrada y el IV concatenados
        return encryptedKeyBase64 + ":" + ivBase64;
    }

    public void receiveAESKey(String encryptedKeyAndIv) throws Exception {
        // Separar la clave cifrada y el IV
        String[] parts = encryptedKeyAndIv.split(":");
        byte[] encryptedAESKey = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);

        // Descifrar la clave AES con la clave privada (RSA)
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAESKey);
        this.aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        this.ivParameterSpec = new IvParameterSpec(iv);
    }

    public String encryptMessage(String message) throws Exception {
        if (aesKey == null || ivParameterSpec == null) {
            throw new IllegalStateException("La clave AES no ha sido intercambiada.");
        }

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);
        byte[] encryptedBytes = aesCipher.doFinal(message.getBytes("UTF-8"));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decryptMessage(String encryptedMessage) throws Exception {
        if (aesKey == null || ivParameterSpec == null) {
            throw new IllegalStateException("La clave AES no ha sido intercambiada.");
        }

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
        byte[] decryptedBytes = aesCipher.doFinal(Base64.getDecoder().decode(encryptedMessage));

        return new String(decryptedBytes, "UTF-8");
    }

    public X509Certificate getPartnerCertificate() {
        return partnerCertificate;
    }
}
