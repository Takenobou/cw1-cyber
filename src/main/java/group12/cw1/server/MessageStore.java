package group12.cw1.server;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

// A ConcurrentHashMap to simulate a simple message store
public class MessageStore {
    private static final ConcurrentHashMap<String, ArrayList<Message>> messages = new ConcurrentHashMap<>();

    public static void addMessage(Message message) {
        messages.computeIfAbsent(message.getRecipient(), k -> new ArrayList<>()).add(message);
    }

    public static ArrayList<Message> getMessagesForRecipient(String recipient) {
        return messages.getOrDefault(recipient, new ArrayList<>());
    }
}
