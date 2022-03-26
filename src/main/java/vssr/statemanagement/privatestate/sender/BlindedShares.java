package vssr.statemanagement.privatestate.sender;

import vssr.RecoveryContribution;
import vss.commitment.Commitment;

public class BlindedShares {
    private final byte[][] share;
    private final Commitment[] commitment;
    private final RecoveryContribution[] contributions;
    
    public BlindedShares(byte[][] share, Commitment[] commitment, RecoveryContribution[] contributions) {
        this.share = share;
        this.commitment = commitment;
        this.contributions = contributions;
    }
    
    public byte[][] getShare() {
        return this.share;
    }
    
    public Commitment[] getCommitment() {
        return this.commitment;
    }
    
    public RecoveryContribution[] getContributions() {
        return this.contributions;
    }
}
