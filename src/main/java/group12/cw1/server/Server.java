package group12.cw1.server;

import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.FileHandler;
import java.util.logging.SimpleFormatter;

public class Server {

    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private static final String SERVER_ID = "server";

    static {
        // Configure logger with handler and formatter
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
        // Check if the program was run with the correct number of arguments
        if (args.length != 1) {
            logger.severe("Usage: java Server <port>");
            return;
        }

        int port = Integer.parseInt(args[0]);
        String privateKeyFile = SERVER_ID + ".prv";

        // Declare serverPrivateKey outside the try block to check for exceptions related to key loading
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

        // Now start the server socket within the try-with-resources statement
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
                    // Handle other unexpected exceptions, if necessary, or re-throw them
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

                // Receive encrypted userid/message from client
                String encryptedData = in.readLine();
                System.out.println("Received encrypted data: " + encryptedData);

                // Decrypt the received data using the server's private key
                String decryptedData = decryptMessage(encryptedData, serverPrivateKey);
                System.out.println("Decrypted data: " + decryptedData);

                // Acknowledge the decryption (this could be more meaningful based on your protocol)
                out.write("ACK\n");
                out.flush();

                // Process decrypted data (e.g., store or forward the message)
                // For simplicity, assume decryptedData is a message for another user
                // In a real scenario, you should parse decryptedData and take appropriate actions
                // Here, we simply echo back the decrypted data as a proof of concept
                out.write(decryptedData + "\n");
                out.flush();

                // Close client connection after handling
                System.out.println("Message processed...");
                socket.close();
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
    }
}
