package org.hwupathum;

import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

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

    private static void createKeyStore(KeyStore keyStore, String alias, String issuer, char[] password)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            CertificateException, KeyStoreException, OperatorCreationException {

        // Generating a key pair for KEM
        KeyPair keyPair = KeystoreUtil.generateKeyPair("ML-KEM-768", MLKEMParameterSpec.ml_kem_768,
                BouncyCastleProvider.PROVIDER_NAME);
        // Create a KeyPairGenerator for the signing key pair
        KeyPair signingKeyPair = KeystoreUtil.generateKeyPair("RSA",
                new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), BouncyCastleProvider.PROVIDER_NAME);

        // Create a Java Keystore and add the generated key pair and certificate
        KeystoreUtil.addSelfSignedCertificate(keyStore, "issuer", signingKeyPair, issuer, password);
        KeystoreUtil.addCertificate(keyStore, alias, signingKeyPair, keyPair, issuer, password);
        System.out.println("Key pair and certificate added to Keystore successfully!");

    }

    private static char[] getPasswordFromConsole(Scanner scanner) {

        Console console = System.console();
        if (console == null) {
            System.out.print("Enter Keystore Password: ");
            String password = scanner.nextLine();
            return password.toCharArray();
        }
        char[] password = console.readPassword("Enter Keystore Password: ");
        char[] verifyPassword = console.readPassword("Re-enter new password: ");
        if (password.length > 0 && Arrays.equals(password, verifyPassword)) {
            return password;
        }
        System.out.print("Error: Passwords do not match\n");
        return new char[0];
    }

    private static String getIssuerFromConsole(Scanner scanner) {

        System.out.print("What is your first and last name?\n [Unknown]: ");
        String cn = scanner.nextLine().trim();
        if (cn.isEmpty()) cn = "Unknown";

        System.out.print("What is the name of your organizational unit?\n [Unknown]: ");
        String ou = scanner.nextLine().trim();
        if (ou.isEmpty()) ou = "Unknown";

        System.out.print("What is the name of your organization?\n [Unknown]: ");
        String o = scanner.nextLine().trim();
        if (o.isEmpty()) o = "Unknown";

        System.out.print("What is the name of your City or Locality?\n [Unknown]: ");
        String l = scanner.nextLine().trim();
        if (l.isEmpty()) l = "Unknown";

        System.out.print("What is the name of your State or Province?\n [Unknown]: ");
        String st = scanner.nextLine().trim();
        if (st.isEmpty()) st = "Unknown";

        System.out.print("What is the two-letter country code for this unit?\n [Unknown]: ");
        String c = scanner.nextLine().trim();
        if (c.isEmpty()) c = "Unknown";

        String issuer = String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", cn, ou, o, l, st, c);
        System.out.printf("Is %s correct?\n [no]: ", issuer);
        String confirmation = scanner.nextLine().trim().toLowerCase();
        if (confirmation.equalsIgnoreCase("y") || confirmation.equalsIgnoreCase("yes")) {
            return issuer;
        } else {
            return getIssuerFromConsole(scanner);
        }
    }

    public static void main(String[] args)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchProviderException, OperatorCreationException {

        KeyStore keyStore;

        Security.addProvider(new BouncyCastleProvider());

        // Create a Scanner object to read input from the command line
        Scanner scanner = new Scanner(System.in);

        // Prompt the user for input
        System.out.print("Enter keystore name \n[keystore.p12]: ");
        String keystoreName = scanner.nextLine(); // Read the input as a string
        if (keystoreName.isEmpty()) {
            keystoreName = "keystore.p12";
        }

        System.out.print("Enter certificate alias \n[alias]: " );
        String alias = scanner.nextLine();
        if (alias.isEmpty()) {
            alias = "alias";
        }

        char[] password = getPasswordFromConsole(scanner);
        if (password.length == 0) {
            return;
        }

        String issuer = getIssuerFromConsole(scanner);

        keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, password);
        createKeyStore(keyStore, alias, issuer, password);

        // Store keystore in a file
        keyStore.store(new FileOutputStream(keystoreName), password);
    }
}