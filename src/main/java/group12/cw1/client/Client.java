package group12.cw1.client;

import java.io.*;
import java.net.Socket;
import java.security.*;
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
        String serverPublicKeyFile = "server.pub"; // Correctly loading the server's public key

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

                // Prompt user to enter a message
                System.out.println("You are now connected to the server. Enter a message:");
                BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
                String messageToSend = userInput.readLine();

                // Encrypt and send the message to the server
                String encryptedMessage = encrypt(messageToSend, serverPublicKey);
                out.println(encryptedMessage);

                logger.info("Message sent to the server: " + messageToSend);

                // Optional: Wait for response from the server
                String response = in.readLine();
                System.out.println("Server response: " + response);
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

    private static String encrypt(String data, PublicKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}
