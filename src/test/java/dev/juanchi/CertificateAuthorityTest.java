package dev.juanchi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CertificateAuthorityTest {

    @BeforeAll
    public static void setup() {
        // Registra el proveedor BouncyCastle para asegurarte de que esté disponible
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerateRootCertificate() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        assertNotNull(CertificateAuthority.generateRootCertificate(keyPair));
    }
}
