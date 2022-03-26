package vssr.statemanagement.recovery;

import java.util.concurrent.ExecutorService;
import java.util.LinkedList;
import vss.facade.SecretSharingException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import vssr.Configuration;
import vssr.VSSRShare;
import java.util.Iterator;
import vssr.RecoveryContribution;
import java.util.Map;
import java.math.BigInteger;
import vssr.statemanagement.ReconstructionCompleted;
import vssr.server.ServerConfidentialityScheme;
import bftsmart.reconfiguration.ServerViewController;
import vssr.statemanagement.privatestate.receiver.BlindedStateHandler;

public class RecoveryBlindedStateHandler extends BlindedStateHandler {
    public RecoveryBlindedStateHandler(ServerViewController svController, int serverPort, int f, int quorum,
                                       int stateSenderReplica, ServerConfidentialityScheme confidentialityScheme,
                                       ReconstructionCompleted reconstructionListener) {
        super(svController, serverPort, f, quorum, stateSenderReplica, confidentialityScheme, reconstructionListener);
    }
    
    @Override
    protected BigInteger[] reconstructBlindedShares(int from, byte[][] shares) {
        BigInteger[] result = new BigInteger[shares.length];
        for (int i = 0; i < result.length; ++i) {
            result[i] = new BigInteger(confidentialityScheme.decryptData(from, shares[i]));
        }
        return result;
    }
    
    @Override
    protected Iterator<VSSRShare> reconstructShares(int nShares, Map<BigInteger, RecoveryContribution[]> allBlindedShares) {
        ExecutorService executorService = Executors.newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        CountDownLatch latch = new CountDownLatch(nShares);
        VSSRShare[] recoveredShares = new VSSRShare[nShares];
        BigInteger[] shareholders = new BigInteger[allBlindedShares.size()];
        int k = 0;
        for (BigInteger shareholder : allBlindedShares.keySet()) {
            shareholders[k++] = shareholder;
        }
        for (int i = 0; i < nShares; ++i) {
            RecoveryContribution[] blindedShares = new RecoveryContribution[shareholders.length];
            for (int j = 0; j < shareholders.length; ++j) {
                blindedShares[j] = allBlindedShares.get(shareholders[j])[i];
            }
            int finalI = i;
            executorService.execute(() -> {
                try {
                    VSSRShare recoveredShare = confidentialityScheme.recoverShare(blindedShares);
                    if (recoveredShare == null) {
                        return;
                    }
                    else {
                        recoveredShares[finalI] = recoveredShare;
                    }
                } catch (SecretSharingException e) {
                    this.logger.error("Failed to recover a share.", e);
                }
                latch.countDown();
            });
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        executorService.shutdown();
        LinkedList<VSSRShare> result = new LinkedList<>();
        for (VSSRShare refreshedShare : recoveredShares) {
            if (refreshedShare == null) {
                return null;
            }
            result.add(refreshedShare);
        }
        return result.iterator();
    }
}
