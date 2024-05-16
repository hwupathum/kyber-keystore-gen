package org.hwupathum;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;

public class KeystoreUtil {

    private static final String SIGNING_ALGORITHM = "SHA256withRSA";
    private static final String ISSUER = "localhost, OU=WSO2, O=WSO2, L=Mountain View, ST=CA, C=US";


    private KeystoreUtil() {}

    public static void addSelfSignedCertificate(KeyStore keyStore, String alias, KeyPair keyPair, char[] password)
            throws CertificateException, OperatorCreationException, KeyStoreException {

        X509Certificate
                caCertificate = KeystoreUtil.generateCertificate(keyPair.getPublic(), keyPair.getPrivate(), ISSUER, ISSUER);
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password, new Certificate[]{caCertificate});
    }

    public static void addCertificate(KeyStore keyStore, String alias, KeyPair signingKeyPair, KeyPair keyPair, char[] password)
            throws CertificateException, OperatorCreationException, KeyStoreException {

        X509Certificate signingCert = KeystoreUtil.generateCertificate(signingKeyPair.getPublic(), signingKeyPair.getPrivate(), ISSUER, ISSUER);
        PrivateKey signingKey = signingKeyPair.getPrivate();
        X509Certificate certificate = KeystoreUtil.generateCertificate(keyPair.getPublic(), signingKey, ISSUER, ISSUER);
        Certificate[] chain = new Certificate[]{certificate, signingCert};
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password, chain);
    }

    public static KeyPair generateKeyPair(String algorithm, AlgorithmParameterSpec algorithmParameterSpec, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
        keyPairGenerator.initialize(algorithmParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }


    public static X509Certificate generateCertificate(PublicKey certPublicKey, PrivateKey signingPrivateKey, String issuerName, String subjectName)
            throws OperatorCreationException, CertificateException {

        // Generate a signed X.509 certificate
        X500Name issuer = new X500Name("CN=" + issuerName);
        X500Name subject = new X500Name("CN=" + subjectName);
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30);
        Date notAfter = new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 10));
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(certPublicKey.getEncoded());
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(new SecureRandom().nextInt()),
                notBefore,
                notAfter,
                subject,
                subPubKeyInfo
        );
        // Use certificate converter to create the X.509 certificate
        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return certConverter.getCertificate(certBuilder.build(
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(SIGNING_ALGORITHM)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signingPrivateKey)));
    }

}
