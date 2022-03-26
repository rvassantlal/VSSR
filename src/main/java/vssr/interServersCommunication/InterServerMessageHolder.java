package vssr.interServersCommunication;

import bftsmart.tom.MessageContext;

public class InterServerMessageHolder {
    private final InterServersMessageType type;
    private final byte[] serializedMessage;
    private final MessageContext messageContext;
    
    public InterServerMessageHolder(InterServersMessageType type, byte[] serializedMessage, MessageContext messageContext) {
        this.type = type;
        this.serializedMessage = serializedMessage;
        this.messageContext = messageContext;
    }
    
    public InterServersMessageType getType() {
        return this.type;
    }
    
    public byte[] getSerializedMessage() {
        return this.serializedMessage;
    }
    
    public MessageContext getMessageContext() {
        return this.messageContext;
    }
}
