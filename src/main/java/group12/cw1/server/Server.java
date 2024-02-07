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
                String clientId = decryptMessage(encryptedClientId, serverPrivateKey);
                System.out.println("Client ID: " + clientId);

                // Step 2: Send stored messages to the client
                ArrayList<Message> messagesForClient = MessageStore.getMessagesForRecipient(clientId);
                out.write(messagesForClient.size() + "\n"); // Inform the client about the number of messages
                out.flush();

                for (Message msg : messagesForClient) {
                    String encryptedMessage = encryptMessageForClient(msg.getContent(), clientId); // Encrypt each message with the recipient's public key
                    out.write(encryptedMessage + "\n");
                    out.flush();
                }

                // Step 3: Listen for a new message
                String newEncryptedMessage = in.readLine();
                while (newEncryptedMessage != null && !newEncryptedMessage.isEmpty()) {
                    String decryptedMessage = decryptMessage(newEncryptedMessage, serverPrivateKey);
                    System.out.println("Received message: " + decryptedMessage);

                    String[] parts = decryptedMessage.split(":", 2);
                    if (parts.length == 2) { // Ensure the message format is correct
                        String recipientId = parts[0];
                        String messageContent = parts[1];
                        MessageStore.addMessage(new Message(clientId, recipientId, messageContent, new Date())); // Store the new message
                    }

                    // Optionally, wait for more messages or close the connection
                    newEncryptedMessage = in.readLine(); // For continuous communication, remove or adjust this line according to your protocol
                }

                System.out.println("Client " + clientId + " disconnected.");
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Error handling client connection", e);
            } catch (GeneralSecurityException e) {
                logger.log(Level.SEVERE, "Error decrypting message", e);
            }
        }


        private String decryptMessage(String encryptedMessage, PrivateKey privateKey) throws GeneralSecurityException {
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

        private static boolean verifySignature(String data, String signature, PublicKey publicKey) throws GeneralSecurityException {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data.getBytes());
            return sig.verify(Base64.getDecoder().decode(signature));
        }

    }
}
