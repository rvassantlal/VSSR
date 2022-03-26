package vssr;

public enum MessageType {
    CLIENT, 
    APPLICATION;
    
    public static MessageType[] values = values();
    
    public static MessageType getMessageType(int ordinal) {
        return MessageType.values[ordinal];
    }
}
