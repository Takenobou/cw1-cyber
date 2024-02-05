package group12.cw1.server;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

public class MessageStore {
    private static final ConcurrentHashMap<String, ArrayList<Message>> messages = new ConcurrentHashMap<>();

    public static void addMessage(Message message) {
        messages.computeIfAbsent(encryptRecipientUserId(message.getRecipient()), k -> new ArrayList<>()).add(message);
    }

    public static ArrayList<Message> getMessagesForRecipient(String recipientEncryptedUserId) {
        return messages.getOrDefault(recipientEncryptedUserId, new ArrayList<>());
    }

    // Dummy encryption method for recipient user ID
    private static String encryptRecipientUserId(String recipientUserId) {
        // Implement encryption logic here
        return recipientUserId; // Placeholder, should return encrypted user ID
    }
}