package vssr.dprf;

import java.math.BigInteger;

public class DPRFPrivateParameters {
    private final BigInteger alphaShare;
    
    public DPRFPrivateParameters(BigInteger alphaShare) {
        this.alphaShare = alphaShare;
    }
    
    public BigInteger getAlphaShare() {
        return alphaShare;
    }
    
    @Override
    public String toString() {
        return "DPRFPrivateParameters{alphaShare=" + alphaShare + '}';
    }
}
