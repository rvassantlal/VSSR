package vssr.client;

import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;
import org.slf4j.Logger;
import bftsmart.tom.util.Extractor;
import java.util.Comparator;

public abstract class ServersResponseHandler implements Comparator<byte[]>, Extractor {
    protected final Logger logger;
    protected CommitmentScheme commitmentScheme;
    protected ClientConfidentialityScheme confidentialityScheme;
    
    public ServersResponseHandler() {
        logger = LoggerFactory.getLogger("confidential");
    }
    
    public void setClientConfidentialityScheme(final ClientConfidentialityScheme confidentialityScheme) {
        this.confidentialityScheme = confidentialityScheme;
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
    }
    
    public abstract void reset();
}
