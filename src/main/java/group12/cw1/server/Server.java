package group12.cw1.server;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server {

    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private static final String SERVER_ID = "server";
    private static final HashMap<String, PublicKey> publicKeyMap = new HashMap<>();

    static {
        logger.setLevel(Level.ALL);
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

                // Acknowledge connection to client for further communication
                out.write("ACK\n");
                out.flush();

                // Wait for the client to send their ID
                String hashedUserId = in.readLine();
                String encryptedClientId = in.readLine();

                String clientId = decrypt(encryptedClientId, serverPrivateKey);

                System.out.println("Client ID: " + hashedUserId);

                // Send stored messages to the client
                ArrayList<Message> messagesForClient = MessageStore.getMessagesForRecipient(clientId);
                System.out.println("Delivering " + messagesForClient.size() + " new messages...");
                out.write(messagesForClient.size() + "\n");
                out.flush();

                // Send messages to the client
                for (Message msg : messagesForClient) {
                    // Encrypt the message for the client
                    String encryptedMessage = encryptMessageForClient(msg.getContent(), clientId);

                    // Generate a digital signature using the server's private key
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(serverPrivateKey);
                    // Ensure encryptedMessage is not null to avoid NullPointerException
                    assert encryptedMessage != null;
                    signature.update(encryptedMessage.getBytes());
                    byte[] digitalSignature = signature.sign();

                    // Send the encrypted message, timestamp, and signature to the client
                    out.write(msg.getTimestamp().getTime() + "\n");
                    out.flush();
                    out.write(encryptedMessage + "\n");
                    out.flush();
                    out.write(Base64.getEncoder().encodeToString(digitalSignature) + "\n");
                    out.flush();
                }
                // Clear message store for that client
                MessageStore.deleteMessagesForRecipient(clientId);

                // Listen for a new message
                String timestampStr = in.readLine();
                String newEncryptedMessage = in.readLine();

                try {
                    // Check if the encrypted message received is not null
                    if (newEncryptedMessage != null) {
                        byte[] encryptedMessageBytes = Base64.getDecoder().decode(newEncryptedMessage);
                        String decryptedMessage = decrypt(new String(encryptedMessageBytes), serverPrivateKey);

                        // Processing the decrypted messages
                        String[] parts = decryptedMessage.split(":", 2);
                        if (parts.length == 2) {
                            String recipientId = parts[0];
                            String messageContent = parts[1];

                            // Retrieve the recipient's public key from the map
                            PublicKey recipientPublicKey = publicKeyMap.get(recipientId);
                            if (recipientPublicKey == null) {
                                recipientPublicKey = loadPublicKeyForUser(recipientId);
                                publicKeyMap.put(recipientId, recipientPublicKey);
                            }

                            // Store the new message or perform any other processing
                            MessageStore.addMessage(new Message(clientId, recipientId, messageContent, new Date()));

                            System.out.println("Incoming message from: " + clientId);
                            System.out.println("Date: " + timestampStr);
                            System.out.println("Recipient: " + recipientId);
                            System.out.println("Message: " + messageContent);
                        }
                    } else {
                        System.out.println("Received null encrypted message from client or user chose not to send a message.");
                    }
                } catch (BadPaddingException e) {
                    logger.log(Level.INFO, "Decryption failed due to bad padding. Message discarded.");
                    return;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                System.out.println("Client " + hashedUserId + " disconnected.");
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Error handling client connection", e);
            } catch (GeneralSecurityException e) {
                logger.log(Level.SEVERE, "Error decrypting message", e);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
    private static String decrypt(String encryptedMessage, PrivateKey privateKey) throws GeneralSecurityException {
        // Decrypts an RSA-encrypted message using a private key and handles padding exceptions.
        try {
            Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedBytes);
        } catch (BadPaddingException e) {
            // Log and discard the message if BadPaddingException occurs
            logger.log(Level.SEVERE, "BadPaddingException: Incorrect padding, discarding the message", e);
            throw e;
        }
    }

    private static PublicKey loadPublicKeyForUser(String userId) throws Exception {
        // Loads the RSA public key for a user from a .pub file based on the userId.
        String publicKeyFilename = userId + ".pub";
        byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyFilename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private static String encryptMessageForClient(String message, String clientId) {
        // Encrypts a message for a client using the recipient's RSA public key.
        try {
            PublicKey recipientPublicKey = publicKeyMap.get(clientId);
            if (recipientPublicKey == null) {
                recipientPublicKey = loadPublicKeyForUser(clientId);
                publicKeyMap.put(clientId, recipientPublicKey);
            }
            Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
            byte[] encryptedBytes = encryptCipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error encrypting message for " + clientId, e);
            return null;
        }
    }
}
