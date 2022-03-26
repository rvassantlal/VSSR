package vssr.dprf;

import java.math.BigInteger;
import java.util.Map;

public class DPRFParameters {
    private final DPRFPublicParameters publicParameters;
    private final Map<BigInteger, DPRFPrivateParameters> privateParameters;
    
    public DPRFParameters(DPRFPublicParameters publicParameters, Map<BigInteger, DPRFPrivateParameters> privateParameters) {
        this.publicParameters = publicParameters;
        this.privateParameters = privateParameters;
    }
    
    public DPRFPublicParameters getPublicParameters() {
        return publicParameters;
    }
    
    public Map<BigInteger, DPRFPrivateParameters> getPrivateParameters() {
        return privateParameters;
    }
    
    public DPRFPrivateParameters getPrivateParameterOf(BigInteger shareholder) {
        return privateParameters.get(shareholder);
    }
    
    @Override
    public String toString() {
        return "DPRFParameters{publicParameters=" + publicParameters + ",\nprivateParameters=" + privateParameters + '}';
    }
}
