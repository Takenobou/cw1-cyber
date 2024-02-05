package group12.cw1.server;

import java.util.Date;

public class Message {
    private String sender;
    private String recipient; // Consider storing encrypted if necessary
    private String content; // Already encrypted
    private Date timestamp;
    // Optional: include a digital signature property if needed

    public Message(String sender, String recipient, String content, Date timestamp) {
        this.sender = sender;
        this.recipient = recipient;
        this.content = content;
        this.timestamp = timestamp;
    }

    // Getters
    public String getSender() { return sender; }
    public String getRecipient() { return recipient; }
    public String getContent() { return content; }
    public Date getTimestamp() { return timestamp; }
}

