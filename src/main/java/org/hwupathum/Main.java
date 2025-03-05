package org.hwupathum;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import java.io.Console;
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
import java.util.Arrays;
import java.util.Scanner;

public class Main {

    private static final String KEYSTORE_TYPE = "PKCS12";

    private static void createKeyStore(KeyStore keyStore, String alias, char[] password)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            CertificateException, KeyStoreException, OperatorCreationException {

        // Generating a key pair for KEM
        KeyPair keyPair = KeystoreUtil.generateKeyPair("Kyber768", KyberParameterSpec.kyber768,
                BouncyCastlePQCProvider.PROVIDER_NAME);
        // Create a KeyPairGenerator for the signing key pair
        KeyPair signingKeyPair = KeystoreUtil.generateKeyPair("RSA",
                new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), BouncyCastleProvider.PROVIDER_NAME);

        // Create a Java Keystore and add the generated key pair and certificate
        KeystoreUtil.addSelfSignedCertificate(keyStore, "issuer", signingKeyPair, password);
        KeystoreUtil.addCertificate(keyStore, alias, signingKeyPair, keyPair, password);
        System.out.println("Key pair and certificate added to Keystore successfully!");

    }

    private static char[] getPasswordFromConsole(Scanner scanner) {

        Console console = System.console();
        if (console == null) {
            System.out.print("Enter Export Password: ");
            String password = scanner.nextLine();
            return password.toCharArray();
        }
        char[] password = console.readPassword("Enter Keystore Password: ");
        char[] verifyPassword = console.readPassword("Verifying - Enter Keystore Password: ");
        if (Arrays.equals(password, verifyPassword)) {
            return password;
        }
        System.out.print("Error: Passwords do not match\n");
        return new char[0];
    }

    public static void main(String[] args)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, OperatorCreationException {

        KeyStore keyStore;

        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleProvider());

        // Create a Scanner object to read input from the command line
        Scanner scanner = new Scanner(System.in);

        // Prompt the user for input
        System.out.print("Enter keystore name:");
        String keystoreName = scanner.nextLine(); // Read the input as a string

        System.out.print("Enter certificate alias:");
        String alias = scanner.nextLine();

        char[] password = getPasswordFromConsole(scanner);
        if (password.length == 0) {
            return;
        }

        keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, password);
        createKeyStore(keyStore, alias, password);

        // Store keystore in a file
        keyStore.store(new FileOutputStream(keystoreName), password);
    }
}