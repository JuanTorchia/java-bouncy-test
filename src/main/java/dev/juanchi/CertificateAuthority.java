package dev.juanchi;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateAuthority {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final KeyPair rootKeyPair;
    private final X509Certificate rootCertificate;

    public CertificateAuthority() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGen.initialize(2048);
        this.rootKeyPair = keyPairGen.generateKeyPair();
        this.rootCertificate = generateRootCertificate(rootKeyPair);
    }

    static X509Certificate generateRootCertificate(KeyPair keyPair) throws Exception {
        X500Name issuer = new X500Name("CN=Root CA, O=Juanchi.DEV, C=AR");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + (10L * 365 * 24 * 60 * 60 * 1000));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber, notBefore, notAfter, issuer, keyPair.getPublic()
        ).build(signer);

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public X509Certificate generateSignedCertificate(String cn, PublicKey publicKey) throws Exception {
        X500Name subject = new X500Name("CN=" + cn + ", O=Juanchi.DEV, C=AR");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(rootKeyPair.getPrivate());

        X509CertificateHolder certHolder = new JcaX509v3CertificateBuilder(
                new X500Name(rootCertificate.getSubjectX500Principal().getName()),
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(),
                new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000)),
                subject, publicKey
        ).build(signer);

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public X509Certificate getRootCertificate() {
        return rootCertificate;
    }
}
