package group12.cw1;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
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

        // Declare serverPrivateKey outside of the try block to check for exceptions related to key loading
        PrivateKey serverPrivateKey = null;
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
                    new ClientHandler(socket).start();
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

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                logger.info("Handling client connection...");
                // Implement communication with client

                // Close client connection after handling
                socket.close();
                logger.info("Client connection closed.");
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Error handling client connection", e);
            }
        }
    }
}
