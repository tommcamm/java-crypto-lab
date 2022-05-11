package edu.tommy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    public static String gpivK;
    public static String gpubK;

    public static void main(String[] args) {
        System.out.println("Welcome to encryptor");

        if (args.length > 0 && args.length <= 2) {
            if (!new File(args[0]).exists() && !new File(args[1]).exists()) {
                System.err.println("[Error] Arguments passed are not representing a valid path");
                System.out.println("Usage: program.jar [pubkey] [privkey]");
                System.exit(1);
            } else {
                System.out.println("Loaded pub key and priv key from arguments");
                gpubK = args[0];
                gpivK = args[1];
            }
        } else if (args.length > 0) {
            System.err.println("[Error] Invalid number/cobination of arguments");
            System.out.println("Usage: program.jar [pubkey] [privkey]");
            System.exit(1);
        } else {
            setup(true);
        }

        String selection = "";
        do {
            System.out.println("Main menu");

            System.out.println("0. Setup keys");
            System.out.println("1. Encrypt a message");
            System.out.println("2. Decrypt a message");
            System.out.println("3. Sign a message");
            System.out.println("4. Verify a message");
            System.out.println("5. Connect to socket");
            System.out.println("6. Open a socket");
            System.out.println("7. bye bye");

            Scanner scn = new Scanner(System.in);
            selection = scn.next();

            switch (selection) {
                case "0" -> setup(false);
                case "1" -> encryptor();
                case "2" -> decryptor();
                case "3" -> sign();
                case "4" -> verify();
                case "5" -> connectSocket();
                case "7" -> System.out.println("goodbye my friend");
                default -> System.out.println("Invalid selection, please try again");
            }
        } while (!selection.equals("7"));
    }

    public static void connectSocket() {
        Scanner scn = new Scanner(System.in);
        String ip = "";
        int port;

        try {
            System.out.print("Server IP: ");
            ip = scn.next();

            System.out.print("Server port: ");
            port = Integer.parseInt(scn.next());

            ClientSocket client = new ClientSocket();
            client.startConnection(ip, port);

            String message = "";

            System.out.println("Connection with server started, send q for exiting");
            do {
                message = scn.next();
                System.out.println(client.sendMessage(message));

            }while (!message.equals("q"));

            client.stopConnection();

        } catch (IOException e) {
            System.err.println("[Error] Error creating connection with host");
        }

    }

    public static void setup(boolean enforce) {
        String selection = "";
        Scanner scn = new Scanner(System.in);
        do {
            System.out.println("[ENCRYPTOR SETUP]");
            System.out.println("1. select existent keys");
            System.out.println("2. generate new keys");
            if (!enforce)
                System.out.println("<any other key>. back to previous menu");
            selection = scn.next();

            if (selection.equals("1")) {
                System.out.print("Public key path: ");
                gpubK = scn.next();
                System.out.print("Private key path: ");
                gpivK = scn.next();
                if (!new File(gpubK).exists() || !new File(gpivK).exists()) {
                    System.err.println("[Error] Invalid public key or private key path");
                } else {
                    System.out.println("Keys loaded successfully");
                    break;
                }
            } else if (selection.equals("2")) {
                System.out.println("Generating new RSA key pair...");
                try {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(2048);
                    KeyPair kp = kpg.generateKeyPair();

                    FileOutputStream out = new FileOutputStream("gen_priv.der");
                    out.write(kp.getPrivate().getEncoded());
                    out.close();
                    gpivK = "gen_priv.der";
                    System.out.println("Generated " + gpivK);

                    out = new FileOutputStream("gen_pub.der");
                    out.write(kp.getPublic().getEncoded());
                    out.close();
                    gpubK = "gen_pub.der";
                    System.out.println("Generated "+ gpubK);

                    System.out.println("Successfully Generated and loaded the new key pair set");
                    break;
                } catch (NoSuchAlgorithmException e) {
                    System.err.println("[Error] key generation failed!");
                } catch (IOException e) {
                    System.err.println("[Error] unable to write key file");
                }
            } else if (!enforce) {
                break;
            }
        } while (true);
        }

    public static void encryptor() {
        Scanner scn = new Scanner(System.in);
        String message = "";

        System.out.print("Message to encrypt: ");
        message = scn.next();

        System.out.println("Encrypted message: " + encryptMessage(message));

    }

    public static void decryptor() {
        Scanner scn = new Scanner(System.in);
        String message = "";

        System.out.print("Message to decrypt: ");
        message = scn.next();

        System.out.println("Decrypted message: " + decryptMessage(message));
    }

    public static void sign() {
        Scanner scn = new Scanner(System.in);
        String message = "";

        System.out.print("Message to sign: ");
        message = scn.next();

        System.out.println("Signature: " + signMessage(message));

    }

    public static void verify() {
        Scanner scn = new Scanner(System.in);
        String message = "";
        String signature = "";

        System.out.print("Message to verify: ");
        message = scn.next();

        System.out.print("Signature for verification: ");
        signature = scn.next();

        if (verifyMessage(message, signature)) {
            System.out.println("Verification OK!");
        } else {
            System.out.println("Failed verification!");
        }
    }


    public static String encryptMessage(String message) {
        String result = "";
        try {
            PublicKey pubK = getPubKey(gpubK);
            Cipher cipher = Cipher .getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pubK);
            byte[] cipherText = cipher.doFinal(message.getBytes());
            result = new String(Base64.getEncoder().encode(cipherText));

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
        return result;
    }

    public static String decryptMessage(String encryptedMessage) {
        String result = "";
        try {
            byte[] decodedMsg = Base64.getDecoder().decode(encryptedMessage.getBytes());

            PrivateKey privK = getPrivKey(gpivK);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privK);

            result = new String(cipher.doFinal(decodedMsg));
        } catch (BadPaddingException|IllegalArgumentException e ) {
            System.err.println("[Error] Can't decrypt! wrong key or message data");
        }
        catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
        return result;
    }

    public static String signMessage(String msg) {
        String result = "";
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(getPrivKey(gpivK));
            byte[] data = msg.getBytes();
            signature.update(data);
            byte[] dataSig = signature.sign();
            result = new String(Base64.getEncoder().encode(dataSig));

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
        return result;
    }

    public static boolean verifyMessage(String msg, String sign) {
        boolean result = false;
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(getPubKey(gpubK));
            signature.update(msg.getBytes());

            return signature.verify(Base64.getDecoder().decode(sign.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
        return result;
    }

    public static PrivateKey getPrivKey (String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePrivate(spec);
    }

    public static PublicKey getPubKey (String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

}
