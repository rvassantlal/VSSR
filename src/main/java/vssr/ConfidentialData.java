package vssr;

import vss.secretsharing.VerifiableShare;
import java.util.Arrays;
import java.io.ObjectInput;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.Externalizable;

public class ConfidentialData implements Externalizable {
    private VSSRShare share;
    
    public ConfidentialData() {
    }
    
    public ConfidentialData(VSSRShare share) {
        this.share = share;
    }
    
    public VSSRShare getShare() {
        return this.share;
    }
    
    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        share.writeExternal(out);
    }
    
    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        share = new VSSRShare();
        share.readExternal(in);
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || this.getClass() != o.getClass()) {
            return false;
        }
        ConfidentialData that = (ConfidentialData)o;
        VerifiableShare[] vs1 = this.share.getVerifiableShares();
        VerifiableShare[] vs2 = that.getShare().getVerifiableShares();
        if (vs1.length != vs2.length) {
            return false;
        }
        if (!this.share.getR().equals(that.getShare().getR())) {
            return false;
        }
        for (int i = 0; i < vs1.length; ++i) {
            VerifiableShare share2 = vs2[i];
            VerifiableShare share3 = vs1[i];
            if (!Arrays.equals(share3.getSharedData(), share2.getSharedData()) || !share3.getCommitments().isOfSameSecret(share2.getCommitments())) {
                return false;
            }
        }
        return true;
    }
    
    @Override
    public int hashCode() {
        int result = this.share.getR().hashCode();
        for (final VerifiableShare verifiableShare : this.share.getVerifiableShares()) {
            result = 31 * result + Arrays.hashCode(verifiableShare.getSharedData());
            result = 31 * result + verifiableShare.getCommitments().consistentHash();
        }
        return result;
    }
}
