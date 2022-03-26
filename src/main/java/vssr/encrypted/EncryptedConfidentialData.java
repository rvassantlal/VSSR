package vssr.encrypted;

import java.util.Arrays;
import java.io.ObjectInput;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.Externalizable;

public class EncryptedConfidentialData implements Externalizable {
    private EncryptedVerifiableShare share;
    
    public EncryptedConfidentialData() {
    }
    
    public EncryptedConfidentialData(EncryptedVerifiableShare share) {
        this.share = share;
    }
    
    public EncryptedVerifiableShare getShare() {
        return this.share;
    }
    
    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        this.share.writeExternal(out);
    }
    
    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        share = new EncryptedVerifiableShare();
        share.readExternal(in);
    }
    
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || this.getClass() != o.getClass()) {
            return false;
        }
        final EncryptedConfidentialData that = (EncryptedConfidentialData)o;
        return Arrays.equals(this.share.getSharedData(), that.share.getSharedData()) && this.share.getCommitments().isOfSameSecret(that.share.getCommitments());
    }
    
    @Override
    public int hashCode() {
        int result = Arrays.hashCode(this.share.getSharedData());
        result = 31 * result + this.share.getCommitments().consistentHash();
        return result;
    }
}
