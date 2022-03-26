package vssr.statemanagement.privatestate.commitments;

import java.util.Map;
import java.math.BigInteger;
import java.util.Set;
import vss.commitment.Commitment;

public interface BlindedCommitmentHandler {
    void handleNewCommitments(int from, Commitment[] commitments, byte[] commitmentsHash);
    
    boolean prepareCommitments();
    
    Map<BigInteger, Commitment[]> readAllCommitments(Set<BigInteger> shareholders);
}
