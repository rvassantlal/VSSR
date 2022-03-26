package vssr.statemanagement;

import bftsmart.tom.server.defaultservices.DefaultApplicationState;

public interface ReconstructionCompleted {
    void onReconstructionCompleted(DefaultApplicationState p0);
}
