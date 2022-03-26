package vssr;

import java.util.Arrays;
import vss.commitment.Commitment;
import vssr.dprf.DPRFContribution;
import java.math.BigInteger;

public class RecoveryContribution {
    private BigInteger r;
    private BigInteger shareholder;
    private DPRFContribution dprfContribution;
    private BigInteger recoveringShare;
    private Commitment shareCommitment;
    private Commitment recoveringCommitment;
    private byte[] sharedData;
    
    public RecoveryContribution() {
    }
    
    public RecoveryContribution(BigInteger r, BigInteger shareholder, DPRFContribution contribute,
                                BigInteger recoveringShare, Commitment shareCommitment, Commitment recoveringCommitment,
                                byte[] sharedData) {
        this.r = r;
        this.shareholder = shareholder;
        this.dprfContribution = contribute;
        this.recoveringShare = recoveringShare;
        this.shareCommitment = shareCommitment;
        this.recoveringCommitment = recoveringCommitment;
        this.sharedData = sharedData;
    }
    
    public BigInteger getR() {
        return r;
    }
    
    public BigInteger getShareholder() {
        return shareholder;
    }
    
    public BigInteger getRecoveringShare() {
        return recoveringShare;
    }
    
    public Commitment getRecoveringCommitment() {
        return recoveringCommitment;
    }
    
    public Commitment getShareCommitment() {
        return shareCommitment;
    }
    
    public void setR(BigInteger r) {
        this.r = r;
    }
    
    public void setRecoveringCommitment(Commitment recoveringCommitment) {
        this.recoveringCommitment = recoveringCommitment;
    }
    
    public void setShareholder(BigInteger shareholder) {
        this.shareholder = shareholder;
    }
    
    public void setDPRFContribution(DPRFContribution dprfContribution) {
        this.dprfContribution = dprfContribution;
    }
    
    public void setRecoveringShare(BigInteger recoveringShare) {
        this.recoveringShare = recoveringShare;
    }
    
    public void setSharedData(byte[] sharedData) {
        this.sharedData = sharedData;
    }
    
    public void setShareCommitment(Commitment shareCommitment) {
        this.shareCommitment = shareCommitment;
    }
    
    public DPRFContribution getDPRFContribution() {
        return dprfContribution;
    }
    
    public byte[] getSharedData() {
        return sharedData;
    }
    
    @Override
    public String toString() {
        return "RecoveryContribution{r=" + r + ",\nshareholder=" + shareholder + ",\ndprfContribution="
                + dprfContribution + ",\nrecoveringShare=" + recoveringShare + ",\nshareCommitment="
                + shareCommitment + ",\nrecoveringCommitment=" + recoveringCommitment + ",\nsharedData="
                + Arrays.toString(sharedData) + '}';
    }
}
