package vssr.statemanagement.recovery;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import vssr.RecoveryContribution;
import vss.commitment.Commitment;
import java.util.concurrent.Executors;
import vssr.Configuration;
import vssr.statemanagement.privatestate.sender.BlindedShares;
import vssr.VSSRShare;
import java.util.LinkedList;
import vssr.server.ServerConfidentialityScheme;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.reconfiguration.ServerViewController;
import vssr.statemanagement.privatestate.sender.BlindedStateSender;

public class RecoveryBlindedStateSender extends BlindedStateSender {
    public RecoveryBlindedStateSender(ServerViewController svController, DefaultApplicationState applicationState,
                                      int blindedStateReceiverPort, ServerConfidentialityScheme confidentialityScheme,
                                      boolean iAmStateSender, int... blindedStateReceivers) {
        super(svController, applicationState, blindedStateReceiverPort, confidentialityScheme, iAmStateSender, blindedStateReceivers);
    }
    
    @Override
    protected BlindedShares computeBlindedShares(LinkedList<VSSRShare> shares) {
        logger.debug("Computing blinded shares");
        ExecutorService executorService = Executors.newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        int nShares = shares.size();
        byte[][] resultingShares = new byte[nShares][];
        Commitment[] resultingCommitments = new Commitment[nShares * 2];
        RecoveryContribution[] resultingContribution = new RecoveryContribution[nShares];
        Iterator<VSSRShare> shareIterator = shares.iterator();
        CountDownLatch latch = new CountDownLatch(nShares);
        int recoveringServer = blindedStateReceivers[0];
        BigInteger recoveringShareholder = confidentialityScheme.getShareholder(recoveringServer);
        for (int i = 0; i < nShares; ++i) {
            VSSRShare share = shareIterator.next();
            int finalI = i;
            executorService.execute(() -> {
                int index = finalI * 2;
                RecoveryContribution contribution = confidentialityScheme.recoveryContribution(share, recoveringShareholder);
                BigInteger blindedShare = contribution.getRecoveringShare();
                resultingShares[finalI] = confidentialityScheme.encryptDataFor(recoveringServer, blindedShare.toByteArray());
                resultingCommitments[index] = contribution.getShareCommitment();
                resultingCommitments[index + 1] = contribution.getRecoveringCommitment();
                resultingContribution[finalI] = contribution;
                latch.countDown();
            });
        }
        try {
            latch.await();
        }
        catch (InterruptedException e) {
            e.printStackTrace();
        }
        executorService.shutdown();
        return new BlindedShares(resultingShares, resultingCommitments, resultingContribution);
    }
}
