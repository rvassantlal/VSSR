package vssr.statemanagement.privatestate.sender;

import vssr.VSSRShare;
import java.util.LinkedList;

public class SeparatedState {
    private final byte[] commonState;
    private final LinkedList<VSSRShare> shares;
    
    public SeparatedState(byte[] commonState, LinkedList<VSSRShare> shares) {
        this.commonState = commonState;
        this.shares = shares;
    }
    
    public byte[] getCommonState() {
        return this.commonState;
    }
    
    public LinkedList<VSSRShare> getShares() {
        return this.shares;
    }
}
