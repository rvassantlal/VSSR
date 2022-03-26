package vssr.dprf;

import java.util.Map;
import java.math.BigInteger;

public class DPRFPublicParameters {
    private final BigInteger h;
    private final BigInteger hAlpha;
    private final Map<BigInteger, BigInteger> hShares;
    
    public DPRFPublicParameters(BigInteger h, BigInteger hAlpha, Map<BigInteger, BigInteger> hShares) {
        this.h = h;
        this.hAlpha = hAlpha;
        this.hShares = hShares;
    }
    
    public BigInteger getH() {
        return h;
    }
    
    public BigInteger getHAlpha() {
        return hAlpha;
    }
    
    public BigInteger getHSharesOf(BigInteger shareholder) {
        return hShares.get(shareholder);
    }
    
    @Override
    public String toString() {
        return "DPRFPublicParameters{h=" + h + ",\nhAlpha=" + hAlpha + ",\nhShares=" + hShares + '}';
    }
}
