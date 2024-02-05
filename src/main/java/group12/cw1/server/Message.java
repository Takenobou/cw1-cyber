package group12.cw1.server;

import java.util.Date;

public class Message {
    private String sender;
    private String recipient;
    private String content;
    private Date timestamp;

    public Message(String sender, String recipient, String content, Date timestamp) {
        this.sender = sender;
        this.recipient = recipient;
        this.content = content;
        this.timestamp = timestamp;
    }

    public String getSender() {
        return sender;
    }

    public String getRecipient() {
        return recipient;
    }

    public String getContent() {
        return content;
    }

    public Date getTimestamp() {
        return timestamp;
    }
}

