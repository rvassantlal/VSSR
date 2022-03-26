package vssr.statemanagement;

import bftsmart.tom.MessageContext;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class ConfidentialStateLog {
    private final Logger logger;
    private final CommandsInfo[] messageBatches;
    private int lastCheckpointCID;
    private byte[] state;
    private byte[] stateHash;
    private int position;
    private int lastCID;
    private final int id;
    
    public ConfidentialStateLog(int id, int k, byte[] initialState, byte[] initialStateHash) {
        this.logger = LoggerFactory.getLogger("confidential");
        this.messageBatches = new CommandsInfo[k - 1];
        this.lastCheckpointCID = -1;
        this.state = initialState;
        this.stateHash = initialStateHash;
        this.position = 0;
        this.lastCID = -1;
        this.id = id;
    }
    
    public void newCheckpoint(byte[] state, byte[] stateHash, int lastConsensusId) {
        Arrays.fill(messageBatches, null);
        this.position = 0;
        this.state = state;
        this.stateHash = stateHash;
        this.lastCheckpointCID = lastConsensusId;
        this.lastCID = lastConsensusId;
    }
    
    public int getLastCheckpointCID() {
        return lastCheckpointCID;
    }
    
    public int getLastCID() {
        return lastCID;
    }
    
    public byte[] getState() {
        return state;
    }
    
    public byte[] getStateHash() {
        return stateHash;
    }
    
    public void addMessageBatch(byte[][] commands, MessageContext[] msgCtx, int lastConsensusId) {
        if (position < messageBatches.length) {
            messageBatches[position] = new CommandsInfo(commands, msgCtx);
            position++;
            lastCID = lastConsensusId;
        }
    }
    
    public CommandsInfo getMessageBatch(int cid) {
        if (cid > lastCheckpointCID && cid <= lastCID) {
            return messageBatches[cid - lastCheckpointCID - 1];
        }
        return null;
    }
    
    public CommandsInfo[] getMessageBatches() {
        return messageBatches;
    }
    
    public int getNumBatches() {
        return position;
    }
    
    public DefaultApplicationState getApplicationState(int cid, boolean setState) {
        logger.info("CID requested: {}. Last checkpoint: {}. Last CID: {}", cid, lastCheckpointCID, lastCID);
        CommandsInfo[] batches = null;
        int lastCID;
        if (cid >= lastCheckpointCID && cid <= this.lastCID) {
            logger.info("Constructing ApplicationState up until CID {}", cid);
            int size = cid - lastCheckpointCID;
            if (size > 0) {
                batches = Arrays.copyOf(messageBatches, size);
            }
            lastCID = cid;
            return new DefaultApplicationState(batches, this.lastCheckpointCID, lastCID, setState ? state : null,
                    stateHash, id);
        }
        return null;
    }
    
    public void update(DefaultApplicationState transState) {
        CommandsInfo[] newMsgBatches = transState.getMessageBatches();
        if (newMsgBatches != null) {
            for (int i = 0; i < newMsgBatches.length; ++i) {
                messageBatches[i] = newMsgBatches[i];
                lastCID = Math.max(lastCID, newMsgBatches[i].msgCtx[0].getConsensusId());
                position = Math.max(position, i + 1);
            }
        }
        lastCheckpointCID = transState.getLastCheckpointCID();
        state = transState.getState();
        stateHash = transState.getStateHash();
    }
}
