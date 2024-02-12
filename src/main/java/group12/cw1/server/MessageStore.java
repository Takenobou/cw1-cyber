package group12.cw1.server;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

public class MessageStore {
    private static final ConcurrentHashMap<String, ArrayList<Message>> messages = new ConcurrentHashMap<>();

    public static void addMessage(Message message) {
        String recipientEncryptedUserId = message.getRecipient();
        messages.computeIfAbsent(recipientEncryptedUserId, k -> new ArrayList<>()).add(message);
    }

    public static ArrayList<Message> getMessagesForRecipient(String recipientHashedUserId) {
        return messages.getOrDefault(recipientHashedUserId, new ArrayList<>());
    }

    public static void deleteMessagesForRecipient(String recipientHashedUserId) {
        messages.remove(recipientHashedUserId);
    }
}