package vssr;

import vss.secretsharing.VerifiableShare;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Arrays;

public class VSSRShare implements Externalizable {
    private BigInteger r;
    private VerifiableShare[] verifiableShares;
    
    public VSSRShare(BigInteger r, VerifiableShare[] verifiableShares) {
        this.r = r;
        this.verifiableShares = verifiableShares;
    }
    
    public VSSRShare() {}
    
    public BigInteger getR() {
        return r;
    }
    
    public VerifiableShare[] getVerifiableShares() {
        return verifiableShares;
    }
    
    public VerifiableShare getShareAtIndex(int index) {
        return verifiableShares[index];
    }
    
    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        if (r == null) {
            out.writeInt(-1);
        }
        else {
            byte[] b = r.toByteArray();
            out.writeInt(b.length);
            out.write(b);
        }
        out.writeInt((verifiableShares == null) ? -1 : verifiableShares.length);
        if (verifiableShares != null) {
            for (VerifiableShare verifiableShare : verifiableShares) {
                out.writeBoolean(verifiableShare != null);
                if (verifiableShare != null) {
                    verifiableShare.writeExternal(out);
                }
            }
        }
    }
    
    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        int len = in.readInt();
        if (len != -1) {
            byte[] b = new byte[len];
            in.readFully(b);
            r = new BigInteger(b);
        }
        int nShares = in.readInt();
        if (nShares != -1) {
            verifiableShares = new VerifiableShare[nShares];
            for (int i = 0; i < nShares; ++i) {
                if (in.readBoolean()) {
                    VerifiableShare vs = new VerifiableShare();
                    vs.readExternal(in);
                    verifiableShares[i] = vs;
                }
            }
        }
    }

    @Override
    public String toString() {
        return "VSSRShare{" +
                "r=" + r +
                ", verifiableShares=" + Arrays.toString(verifiableShares) +
                '}';
    }
}
