package group12.cw1.client;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class Client {
    private static final Logger logger = Logger.getLogger(Client.class.getName());

    static {
        try {
            FileHandler fileHandler = new FileHandler("ClientLog.log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
            logger.setLevel(Level.ALL);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "File logger not working.", e);
        }
    }

    public static void main(String[] args) {
        if (args.length != 3) {
            logger.severe("Usage: java Client <host> <port> <userid>");
            return;
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];
        String serverPublicKeyFile = "server.pub";

        try {
            PublicKey serverPublicKey = loadPublicKey(serverPublicKeyFile);
            logger.info("Server's public key loaded.");

            try (Socket socket = new Socket(host, port);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
                logger.info("Connected to the server as " + userId);

                // Encrypt and send the user ID
                String encryptedUserId = encrypt(userId, serverPublicKey);
                out.println(encryptedUserId);

                // Wait for server acknowledgment
                String ack = in.readLine();
                if (!"ACK".equals(ack)) {
                    logger.severe("Did not receive proper acknowledgment from server.");
                    return;
                }

                // Receive the number of messages stored for the user
                int messageCount = Integer.parseInt(in.readLine());
                System.out.println("You have " + messageCount + " new message(s).");

                for (int i = 0; i < messageCount; i++) {
                    // Assume server sends encrypted messages that client can decrypt with its private key
                    String encryptedMessage = in.readLine();
                    String decryptedMessage = decrypt(encryptedMessage, loadPrivateKey(userId + ".prv"));
                    System.out.println("Message " + (i + 1) + ": " + decryptedMessage);
                }

                // User input to send a new message
                System.out.println("Enter recipient's user ID and message in the format 'recipientId:message'");
                BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
                String newMessage = userInput.readLine();

                // Encrypt and send the new message to the server
                String encryptedNewMessage = encrypt(newMessage, serverPublicKey);
                out.println(encryptedNewMessage);

                logger.info("New message sent to the server.");

                // Wait for server's response to the new message
                String serverResponse = in.readLine();
                System.out.println("Server response: " + serverResponse);
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "IO Exception while connecting or communicating with server", e);
        } catch (GeneralSecurityException e) {
            logger.log(Level.SEVERE, "Security Exception when loading keys", e);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected exception", e);
        }
    }

    private static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static String encrypt(String data, PublicKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedData, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }
}
