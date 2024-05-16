package org.hwupathum;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;

public class Main {

    private static final String KEYSTORE_PASSWORD = "ballerina";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEY_ALIAS = "mlkem-keypair";
    private static final String KEYSTORE_NAME = "mlkem-keystore.p12";

    private static void createKeyStore(KeyStore keyStore)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            CertificateException, KeyStoreException, OperatorCreationException {

        // Generating a key pair for KEM
        KeyPair keyPair = KeystoreUtil.generateKeyPair("Kyber768", KyberParameterSpec.kyber768,
                BouncyCastlePQCProvider.PROVIDER_NAME);
        // Create a KeyPairGenerator for the signing key pair
        KeyPair signingKeyPair = KeystoreUtil.generateKeyPair("RSA",
                new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), BouncyCastleProvider.PROVIDER_NAME);

        // Create a Java Keystore and add the generated key pair and certificate
        KeystoreUtil.addSelfSignedCertificate(keyStore, "issuer", signingKeyPair, KEYSTORE_PASSWORD);
        KeystoreUtil.addCertificate(keyStore, KEY_ALIAS, signingKeyPair, keyPair, KEYSTORE_PASSWORD);
        System.out.println("Key pair and certificate added to Keystore successfully!");

    }

    public static void main(String[] args)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, OperatorCreationException {

        KeyStore keyStore;

        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleProvider());

        keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, KEYSTORE_PASSWORD.toCharArray());
        createKeyStore(keyStore);

        // Store keystore in a file
        keyStore.store(new FileOutputStream(KEYSTORE_NAME), KEYSTORE_PASSWORD.toCharArray());
    }
}