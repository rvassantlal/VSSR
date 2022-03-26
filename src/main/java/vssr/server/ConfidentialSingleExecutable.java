package vssr.server;

import vssr.statemanagement.ConfidentialSnapshot;
import vssr.ConfidentialMessage;
import bftsmart.tom.MessageContext;
import vssr.ConfidentialData;

public interface ConfidentialSingleExecutable
{
    ConfidentialMessage appExecuteOrdered(final byte[] p0, final ConfidentialData[] p1, final MessageContext p2);
    
    ConfidentialMessage appExecuteUnordered(final byte[] p0, final ConfidentialData[] p1, final MessageContext p2);
    
    ConfidentialSnapshot getConfidentialSnapshot();
    
    void installConfidentialSnapshot(final ConfidentialSnapshot p0);
}
