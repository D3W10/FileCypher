package com.g07;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Main {
    private static final String FILE_ALGORITHM = "AES";
    private static final String KEY_ALGORITHM = "RSA";
    private static final int AES_KEY_SIZE = 256;
    private static final String PFX_KEYSTORE_PASSWORD = "changeit";

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("No mode provided");
            printUsage();
            return;
        }
        if (args.length < 2) {
            System.out.println("No input file provided");
            printUsage();
            return;
        }

        String mode = args[0];
        String inputFile = args[1];

        try {
            if (mode.equals("-enc")) {
                if (args.length < 3) {
                    System.out.println("Encryption mode requires a certificate file.");
                    printUsage();
                    return;
                }

                String fileAlg = FILE_ALGORITHM;
                String keyAlg = KEY_ALGORITHM;

                for (int i = 4; i < args.length; i++) {
                    if (args[i].equals("--fileAlg"))
                        fileAlg = args[++i];
                    else if (args[i].equals("--keyAlg"))
                        keyAlg = args[++i];
                }

                encryptFile(inputFile, args[2], fileAlg, keyAlg);
            }
            else if (mode.equals("-dec")) {
                if (args.length < 5) {
                    System.out.println("Decryption mode requires encrypted key file, encrypted content file, and keystore file.");
                    printUsage();
                    return;
                }

                String fileAlg = FILE_ALGORITHM;
                String keyAlg = KEY_ALGORITHM;

                for (int i = 6; i < args.length; i++) {
                    if (args[i].equals("--fileAlg"))
                        fileAlg = args[++i];
                    else if (args[i].equals("--keyAlg"))
                        keyAlg = args[++i];
                }

                decryptFile(inputFile, args[2], args[3], args[4], fileAlg, keyAlg);
            }
            else {
                System.out.println("Invalid mode. Use -enc for encryption or -dec for decryption.");
                printUsage();
            }
        }
        catch (Exception e) {
            System.out.println("An error occured in the app:\n");
            e.printStackTrace(System.out);
        }
    }

    private static void printUsage() {
        System.out.println("\nUsage:\n\tfilecypher [-end|-dec] <inputFile> [<certificateFile>|<encryptedContentFile> <encryptedKeyFile> <keystoreFile>] [--fileAlg <algorithm>] [--keyAlg <algorithm>]");
    }

    private static void encryptFile(String inputFile, String certificateFile, String fileAlg, String keyAlg) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(fileAlg);
        keyGen.init(AES_KEY_SIZE);
        SecretKey secretKey = keyGen.generateKey();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream certFis = new FileInputStream(certificateFile);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certFis);

        try {
            cert.checkValidity();
        }
        catch (CertificateExpiredException e) {
            System.out.println("The provided certificate is no longer valid.");
            return;
        }
        catch (CertificateNotYetValidException e) {
            System.out.println("The provided certificate is not valid yet.");
            return;
        }

        PublicKey publicKey = cert.getPublicKey();

        Cipher aesCipher = Cipher.getInstance(fileAlg);
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] fileContent = Files.readAllBytes(Paths.get(inputFile));
        byte[] encryptedContent = aesCipher.doFinal(fileContent);

        Cipher rsaCipher = Cipher.getInstance(keyAlg);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = rsaCipher.doFinal(secretKey.getEncoded());

        String inputFileName = inputFile.lastIndexOf('.') != -1 ? inputFile.substring(0, inputFile.lastIndexOf('.')) : inputFile;
        Files.write(Paths.get(inputFileName + ".enc"), Base64.getEncoder().encode(encryptedContent));
        Files.write(Paths.get(inputFileName + ".key"), Base64.getEncoder().encode(encryptedKey));

        System.out.println("Encryption completed successfully.");
    }

    private static void decryptFile(String outputFile, String encryptedContentFile, String encryptedKeyFile, String keystoreFile, String fileAlg, String keyAlg) throws Exception {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] pfxKey = PFX_KEYSTORE_PASSWORD.toCharArray();

        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keystore.load(fis, pfxKey);
        }
        if (!keystore.aliases().hasMoreElements())
            throw new NullPointerException("The keystore has no aliases");

        PrivateKey privateKey = (PrivateKey) keystore.getKey(keystore.aliases().nextElement(), pfxKey);
        byte[] encryptedKey = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(encryptedKeyFile)));

        Cipher rsaCipher = Cipher.getInstance(keyAlg);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = rsaCipher.doFinal(encryptedKey);
        SecretKey secretKey = new SecretKeySpec(decryptedKey, fileAlg);

        byte[] encryptedContent = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(encryptedContentFile)));

        Cipher aesCipher = Cipher.getInstance(fileAlg);
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedContent = aesCipher.doFinal(encryptedContent);

        Files.write(Paths.get(outputFile), decryptedContent);

        System.out.println("Decryption completed successfully.");
    }
}