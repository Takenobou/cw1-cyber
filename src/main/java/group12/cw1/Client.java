package group12.cw1;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.logging.FileHandler;
import java.util.logging.SimpleFormatter;

public class Client {

    private static final Logger logger = Logger.getLogger(Client.class.getName());

    static {
        // Configure logger with handler and formatter
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
        // Check if the program was run with the correct number of arguments
        if (args.length != 3) {
            logger.severe("Usage: java Client <host> <port> <userid>");
            return;
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];
        String publicKeyFile = userId + ".pub";

        try {
            PublicKey serverPublicKey = loadPublicKey(publicKeyFile);
            logger.info("Server's public key loaded.");

            // Connect to the server
            try (Socket socket = new Socket(host, port)) {
                logger.info("Connected to the server as " + userId);
                // Implement communication with server

                // Ensure to close the resources properly
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "IO Exception while connecting or communicating with server", e);
        } catch (GeneralSecurityException e) {
            logger.log(Level.SEVERE, "Security Exception when loading keys", e);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected exception", e);
        }
    }

    // Load the RSA public key from a file
    private static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
