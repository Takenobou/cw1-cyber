package group12.cw1.client;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.Cipher;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Date;

public class Client {
    private static final Logger logger = Logger.getLogger(Client.class.getName());

    static {
        logger.setLevel(Level.SEVERE);
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

                // Generate the hashed user ID
                String hashedUserId = hashUserId(userId);

                // Encrypt the user ID using the server's public key
                String encryptedUserId = encrypt(userId, serverPublicKey);

                // Send both the hashed and encrypted user IDs to the server
                out.println(hashedUserId);
                out.println(encryptedUserId);

                // Wait for server acknowledgment
                String ack = in.readLine();
                if (!"ACK".equals(ack)) {
                    logger.severe("Did not receive proper acknowledgment from server.");
                    return;
                }

                // Receive the number of messages stored for the user
                int messageCount = Integer.parseInt(in.readLine());
                System.out.println("There are " + messageCount + " message(s) for you.");

                for (int i = 0; i < messageCount; i++) {
                    long timestamp = Long.parseLong(in.readLine());
                    String encryptedMessage = in.readLine();
                    String digitalSignature = in.readLine();

                    // Verify the digital signature
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initVerify(serverPublicKey);
                    signature.update(encryptedMessage.getBytes());

                    if (signature.verify(Base64.getDecoder().decode(digitalSignature))) {
                        // Decrypt the message if signature is verified
                        String decryptedMessage = decrypt(encryptedMessage, loadPrivateKey(userId + ".prv"));
                        System.out.println("Date: " + new Date(timestamp));
                        System.out.println("Received message: " + decryptedMessage);
                    } else {
                        // Terminate the connection if signature is not verified
                        System.out.println("Digital signature verification failed. Terminating connection.");
                        return;
                    }
                }
                BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));

                while (true) {
                    System.out.print("Do you want to send a message? [y/n]: ");
                    String choice = userInput.readLine();
                    if (choice.equalsIgnoreCase("n")) {
                        break;
                    }
                    else if (choice.equalsIgnoreCase("y")) {
                        System.out.println("Enter recipient's user ID:");
                        String recipientId = userInput.readLine();

                        System.out.println("Enter your message:");
                        String message = userInput.readLine();

                        // Concatenate recipientId and message with a delimiter
                        String newMessage = recipientId + ":" + message;

                        // Get current timestamp
                        Date currentTime = new Date();
                        SimpleDateFormat dateFormat = new SimpleDateFormat("E MMM dd HH:mm:ss zzz yyyy");
                        String formattedTimestamp = dateFormat.format(currentTime);

                        // After encrypting the message
                        byte[] encryptedMessageBytes = encrypt(newMessage, serverPublicKey).getBytes();

                        // Send the encrypted message
                        out.println(formattedTimestamp);
                        out.flush();
                        out.println(Base64.getEncoder().encodeToString(encryptedMessageBytes));
                        out.flush();
                        out.write(recipientId + "\n");
                        out.flush();
                        System.out.println("Encrypted message sent to the server.");
                        logger.info("New message sent to the server.");
                        break;
                    }
                    else {
                        System.out.println("Invalid choice. Please enter 'y' or 'n'.");
                    }
                }
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
        // Loads a public key from a specified file using RSA algorithm.
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        // Loads a private key from a specified file using RSA algorithm.
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static String encrypt(String data, PublicKey key) throws GeneralSecurityException {
        // Encrypts data using an RSA public key.
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedData, PrivateKey privateKey) throws GeneralSecurityException {
        // Decrypts data using an RSA private key.
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }

    private static String hashUserId(String userId) throws NoSuchAlgorithmException {
        // Hashes a userid with a secret prefix using MD5 and returns the hexadecimal string.
        String secret = "gfhk2024:";
        String dataToHash = secret + userId;

        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashBytes = md.digest(dataToHash.getBytes());

        // Convert the byte array to a hexadecimal string
        StringBuilder hexString = new StringBuilder();
        for (byte hashByte : hashBytes) {
            String hex = Integer.toHexString(0xff & hashByte);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}