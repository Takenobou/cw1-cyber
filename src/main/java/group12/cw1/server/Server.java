package group12.cw1.server;

import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.FileHandler;
import java.util.logging.SimpleFormatter;

public class Server {

    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private static final String SERVER_ID = "server";

    static {
        try {
            FileHandler fileHandler = new FileHandler("ServerLog.log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
            logger.setLevel(Level.ALL);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "File logger not working.", e);
        }
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            logger.severe("Usage: java Server <port>");
            return;
        }

        int port = Integer.parseInt(args[0]);
        String privateKeyFile = SERVER_ID + ".prv";

        PrivateKey serverPrivateKey;
        try {
            serverPrivateKey = loadPrivateKey(privateKeyFile);
            logger.info("Server's private key loaded.");
        } catch (GeneralSecurityException e) {
            logger.log(Level.SEVERE, "Security Exception when loading private key", e);
            return;
        } catch (IOException e) {
            logger.log(Level.SEVERE, "IOException when loading private key", e);
            return;
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected exception when loading private key", e);
            return;
        }

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.info("Server is listening on port " + port);

            while (true) {
                try {
                    Socket socket = serverSocket.accept();
                    logger.info("New client connected");

                    // Handle client connection in a separate thread
                    new ClientHandler(socket, serverPrivateKey).start();
                } catch (IOException e) {
                    logger.log(Level.SEVERE, "IO Exception while accepting a connection", e);
                    break;
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Unexpected exception while accepting a connection", e);
                    // TODO: EXPAND EXCEPTION HANDLING
                }
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "IO Exception while starting or running server", e);
        }
    }

    // Load the RSA private key from a file
    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    // ClientHandler class to manage each client connection
    private static class ClientHandler extends Thread {
        private final Socket socket;
        private final PrivateKey serverPrivateKey;

        public ClientHandler(Socket socket, PrivateKey serverPrivateKey) {
            this.socket = socket;
            this.serverPrivateKey = serverPrivateKey;
        }

        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))) {

                // Initially acknowledge connection to client for further communication
                out.write("ACK\n");
                out.flush();

                // Step 1: Wait for the client to send their ID
                String encryptedClientId = in.readLine();
                String clientId = decrypt(encryptedClientId, serverPrivateKey);
                String hashedClientId = hashUserID(clientId);
                System.out.println("Client ID: " + hashedClientId);

                // Step 2: Send stored messages to the client
                ArrayList<Message> messagesForClient = MessageStore.getMessagesForRecipient(clientId);
                out.write(messagesForClient.size() + "\n"); // Inform the client about the number of messages
                out.flush();

                for (Message msg : messagesForClient) {
                    String encryptedMessage = encryptMessageForClient(msg.getContent(), clientId); // Encrypt each message with the recipient's public key
                    out.write(msg.getTimestamp().getTime() + "\n"); // Send timestamp as milliseconds
                    out.flush();
                    out.write(encryptedMessage + "\n");
                    out.flush();
                }

                // Step 3: Listen for a new message
                String timestampStr = in.readLine(); // Read timestamp from client
                String newEncryptedMessage = in.readLine(); // Read encrypted message from client
                String digitalSignatureString = in.readLine(); // Read digital signature from client

                // Verify the signature using the client's public key
                byte[] encryptedMessageBytes = Base64.getDecoder().decode(newEncryptedMessage);
                byte[] digitalSignature = Base64.getDecoder().decode(digitalSignatureString);
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initVerify(loadPublicKeyForUser(clientId));
                signature.update(encryptedMessageBytes);
                boolean signatureVerified = signature.verify(digitalSignature);

                if (signatureVerified) {
                    // Proceed with decryption and processing of the message
                    String decryptedMessage = decrypt(new String(encryptedMessageBytes), serverPrivateKey);
                    // Handle the decrypted message

                    // Processing the decrypted message can go here
                    // For example:
                    String[] parts = decryptedMessage.split(":", 2);
                    if (parts.length == 2) {
                        String recipientId = parts[0];
                        String messageContent = parts[1];
                        // Store the new message or perform any other processing
                        Message newMessage = new Message(clientId, recipientId, messageContent, new Date());

                        // Print the incoming message to the server console
                        System.out.println("Incoming message from: " + clientId);
                        System.out.println("Timestamp: " + newMessage.getTimestamp());
                        System.out.println("Recipient: " + recipientId);
                        System.out.println("Message: " + messageContent);
                    }
                } else {
                    // Signature verification failed, handle the error
                }

                // Print a message when a client disconnects
                System.out.println("Client " + hashedClientId + " disconnected.");
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Error handling client connection", e);
            } catch (GeneralSecurityException e) {
                logger.log(Level.SEVERE, "Error decrypting message", e);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        private String decrypt(String encryptedMessage, PrivateKey privateKey) throws GeneralSecurityException {
            Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedBytes);
        }

        private PublicKey loadPublicKeyForUser(String userId) throws Exception {
            String publicKeyFilename = userId + ".pub";
            byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyFilename));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }

        private String encryptMessageForClient(String message, String clientId) {
            try {
                PublicKey recipientPublicKey = loadPublicKeyForUser(clientId);
                Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                encryptCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
                byte[] encryptedBytes = encryptCipher.doFinal(message.getBytes());
                return Base64.getEncoder().encodeToString(encryptedBytes);
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error encrypting message for " + clientId, e);
                return null; // TODO: HANDLE PROPERLY THIS AINT GONNA CUT IT
            }
        }

        private static String hashUserID(String userID) {
            String secret = "gfhk2024:";
            String input = secret + userID;
            try {
                // Create MD5 hash instance
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(input.getBytes());

                // Convert hash bytes to hexadecimal string
                byte[] digest = md.digest();
                StringBuilder hexString = new StringBuilder();
                for (byte b : digest) {
                    hexString.append(String.format("%02x", b & 0xff));
                }
                return hexString.toString();
            } catch (NoSuchAlgorithmException e) {
                // Handle hashing algorithm not found
                e.printStackTrace();
                return null;
            }
        }
    }
}