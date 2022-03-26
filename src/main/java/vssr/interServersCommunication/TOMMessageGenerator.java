package vssr.interServersCommunication;

import bftsmart.tom.util.TOMUtil;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.core.messages.TOMMessage;
import java.util.Random;
import bftsmart.reconfiguration.ServerViewController;

public class TOMMessageGenerator {
    private final int id;
    private final int session;
    private int orderedSeq;
    private int unorderedSeq;
    private int requestId;
    private final ServerViewController controller;
    
    public TOMMessageGenerator(ServerViewController controller) {
        this.controller = controller;
        this.id = controller.getStaticConf().getProcessId();
        this.session = new Random(System.nanoTime()).nextInt();
    }
    
    public TOMMessage getNextOrdered(byte[] metadata, byte[] payload) {
        return nextMessage(metadata, payload, orderedSeq++, requestId++, TOMMessageType.ORDERED_REQUEST);
    }
    
    public TOMMessage getNextUnordered(byte[] payload) {
        return nextMessage(null, payload, unorderedSeq++, requestId++, TOMMessageType.UNORDERED_REQUEST);
    }
    
    private TOMMessage nextMessage(byte[] metadata, byte[] payload, int sequence, int requestId, TOMMessageType type) {
        TOMMessage msg = new TOMMessage(id, session, sequence, requestId, metadata, payload, new byte[0], controller.getCurrentViewId(), type);
        msg.serializedMessage = TOMMessage.messageToBytes(msg);
        if (controller.getStaticConf().getUseSignatures() == 1) {
            msg.serializedMessageSignature = TOMUtil.signMessage(controller.getStaticConf().getPrivateKey(), msg.serializedMessage);
            msg.signed = true;
        }
        return msg;
    }
}
