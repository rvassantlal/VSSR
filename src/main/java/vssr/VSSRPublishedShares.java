package vssr;

import vss.commitment.Commitment;
import vssr.encrypted.EncryptedShare;

import java.math.BigInteger;

public class VSSRPublishedShares {
    private final BigInteger r;
    private final EncryptedShare[][] shares;
    private final Commitment[] commitments;
    private final byte[] sharedData;
    
    public VSSRPublishedShares(BigInteger r, EncryptedShare[][] shares, Commitment[] commitments, byte[] sharedData) {
        this.r = r;
        this.shares = shares;
        this.commitments = commitments;
        this.sharedData = sharedData;
    }
    
    public BigInteger getR() {
        return this.r;
    }
    
    public Commitment[] getCommitments() {
        return this.commitments;
    }
    
    public byte[] getSharedData() {
        return this.sharedData;
    }
    
    public EncryptedShare[] getShareOf(BigInteger shareholder) {
        EncryptedShare[] result = new EncryptedShare[this.shares.length];
        int i = 0;
        for (EncryptedShare[] encryptedShare : this.shares) {
            for (EncryptedShare share : encryptedShare) {
                if (share.getShareholder().equals(shareholder)) {
                    result[i++] = share;
                }
            }
        }
        if (i != result.length) {
            return null;
        }
        return result;
    }
}
