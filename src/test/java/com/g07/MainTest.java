package com.g07;

import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class MainTest {
    @Test
    public void encryptFile() {
        Main.main(new String[]{"-enc", "testfile.txt", "samples/end-entities/Alice_1.cer"});

        assertTrue(Files.exists(Paths.get("testfile.enc")));
        assertTrue(Files.exists(Paths.get("testfile.key")));
    }

    @Test
    public void encryptFileExplicitAlgorithms() throws IOException {
        Path encFile = Paths.get("testfile.enc");
        Path keyFile = Paths.get("testfile.key");

        Main.main(new String[]{"-enc", "testfile.txt", "samples/end-entities/Alice_1.cer", "--fileAlg", "AES", "--keyAlg", "RSA"});
        assertTrue(Files.exists(encFile));
        assertTrue(Files.exists(keyFile));
        Files.delete(encFile);
        Files.delete(keyFile);

        Main.main(new String[]{"-enc", "testfile.txt", "samples/end-entities/Alice_1.cer", "--fileAlg", "AES"});
        assertTrue(Files.exists(encFile));
        assertTrue(Files.exists(keyFile));
        Files.delete(encFile);
        Files.delete(keyFile);

        Main.main(new String[]{"-enc", "testfile.txt", "samples/end-entities/Alice_1.cer", "--keyAlg", "RSA"});
        assertTrue(Files.exists(encFile));
        assertTrue(Files.exists(keyFile));
        Files.delete(encFile);
        Files.delete(keyFile);
    }

    @Test
    public void decryptFile() throws IOException {
        Main.main(new String[]{"-dec", "outputfile.txt", "testfile.enc", "testfile.key", "samples/pfx/Alice_1.pfx"});

        Path path = Paths.get("outputfile.txt");
        assertTrue(Files.exists(path));

        String original = new String(Files.readAllBytes(Paths.get("testfile.txt")));
        String decoded = new String(Files.readAllBytes(path));
        assertEquals(original, decoded);
    }

    @Test
    public void decryptFileExplicitAlgorithms() throws IOException {
        Path outputFile = Paths.get("outputfile.txt");
        String original = new String(Files.readAllBytes(Paths.get("testfile.txt"))), decoded;

        Main.main(new String[]{"-dec", "outputfile.txt", "testfile.enc", "testfile.key", "samples/pfx/Alice_1.pfx", "--fileAlg", "AES", "--keyAlg", "RSA"});
        assertTrue(Files.exists(outputFile));
        decoded = new String(Files.readAllBytes(outputFile));
        assertEquals(original, decoded);
        Files.delete(outputFile);

        Main.main(new String[]{"-dec", "outputfile.txt", "testfile.enc", "testfile.key", "samples/pfx/Alice_1.pfx", "--fileAlg", "AES"});
        assertTrue(Files.exists(outputFile));
        decoded = new String(Files.readAllBytes(outputFile));
        assertEquals(original, decoded);
        Files.delete(outputFile);

        Main.main(new String[]{"-dec", "outputfile.txt", "testfile.enc", "testfile.key", "samples/pfx/Alice_1.pfx", "--keyAlg", "RSA"});
        assertTrue(Files.exists(outputFile));
        decoded = new String(Files.readAllBytes(outputFile));
        assertEquals(original, decoded);
        Files.delete(outputFile);
    }
}