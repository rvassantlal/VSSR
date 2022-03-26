package vssr.statemanagement;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.SMMessage;
import bftsmart.statemanagement.StateManager;
import bftsmart.tom.core.DeliveryThread;
import bftsmart.tom.core.TOMLayer;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vssr.Configuration;
import vssr.server.ServerConfidentialityScheme;
import vssr.statemanagement.recovery.RecoveryBlindedStateHandler;
import vssr.statemanagement.recovery.RecoveryBlindedStateSender;

import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

public class ConfidentialStateManager extends StateManager implements ReconstructionCompleted {
    private final int SERVER_STATE_LISTENING_PORT;
    private final Logger logger;
    private static final long INIT_TIMEOUT = 3600000L;
    private ServerConfidentialityScheme confidentialityScheme;
    private Timer stateTimer;
    private long timeout;
    private final ReentrantLock lockTimer;
    private long recoveryStartTime;
    private final Set<Integer> usedReplicas;
    
    public ConfidentialStateManager() {
        this.logger = LoggerFactory.getLogger("confidential");
        this.timeout = 3600000L;
        this.lockTimer = new ReentrantLock();
        this.usedReplicas = new HashSet<>();
        this.SERVER_STATE_LISTENING_PORT = Configuration.getInstance().getRecoveryPort();
    }
    
    public void setConfidentialityScheme(ServerConfidentialityScheme confidentialityScheme) {
        this.confidentialityScheme = confidentialityScheme;
    }
    
    public void init(TOMLayer tomLayer, DeliveryThread dt) {
        super.init(tomLayer, dt);
        tomLayer.requestsTimer.Enabled(false);
    }
    
    private int getRandomReplica() {
        int[] processes = SVController.getCurrentViewOtherAcceptors();
        Random rnd = new Random();
        int replica;
        do {
            int i = rnd.nextInt(processes.length);
            replica = processes[i];
        } while (this.usedReplicas.contains(replica));
        usedReplicas.add(replica);
        return replica;
    }
    
    protected void requestState() {
        logger.debug("requestState");
        recoveryStartTime = System.nanoTime();
        if (tomLayer.requestsTimer != null) {
            tomLayer.requestsTimer.clearAll();
        }
        int stateSenderReplica = this.getRandomReplica();
        DefaultSMMessage recoverySMMessage = new DefaultSMMessage(SVController.getStaticConf().getProcessId(),
                waitingCID, 6, null, SVController.getCurrentView(), -1,
                tomLayer.execManager.getCurrentLeader(), stateSenderReplica, SERVER_STATE_LISTENING_PORT);
        logger.info("Replica {} will send full state", stateSenderReplica);
        logger.info("Sending request for state up to CID {} to {}", waitingCID,
                Arrays.toString(SVController.getCurrentViewOtherAcceptors()));
        tomLayer.getCommunication().send(SVController.getCurrentViewOtherAcceptors(), recoverySMMessage);
        tomLayer.requestsTimer.Enabled(false);
        TimerTask stateTask = new TimerTask() {
            @Override
            public void run() {
                logger.info("Timeout to retrieve state");
                SMMessage message = new DefaultSMMessage(SVController.getStaticConf().getProcessId(),
                        waitingCID, 9, null, null, -1, -1, -1, -1);
                triggerTimeout(message);
            }
        };
        int f = SVController.getCurrentViewF();
        int quorum = SVController.getCurrentViewN() - f;
        new RecoveryBlindedStateHandler(SVController, SERVER_STATE_LISTENING_PORT, f, quorum, stateSenderReplica,
                confidentialityScheme, this).start();
        stateTimer = new Timer("State Timer");
        timeout *= 2L;
        stateTimer.schedule(stateTask, this.timeout);
    }
    
    public void stateTimeout() {
        lockTimer.lock();
        logger.debug("Timeout for the replicas that were supposed to send the state. Trying again");
        if (stateTimer != null) {
            stateTimer.cancel();
        }
        reset();
        requestState();
        lockTimer.unlock();
    }
    
    public void SMRequestDeliver(SMMessage msg, boolean isBFT) {
        if (msg instanceof DefaultSMMessage) {
            logger.debug("Received recovery request from {}", msg.getSender());
            if (SVController.getStaticConf().isStateTransferEnabled() && dt.getRecoverer() != null) {
                DefaultApplicationState appState = (DefaultApplicationState)dt.getRecoverer().getState(msg.getCID(), true);
                if (appState == null || appState.getMessageBatches() == null) {
                    logger.warn("Ignoring this state transfer request because app state is null");
                    return;
                }
                DefaultSMMessage defaultSMMessage = (DefaultSMMessage)msg;
                RecoveryStateServerSMMessage response = new RecoveryStateServerSMMessage(
                        SVController.getStaticConf().getProcessId(), appState.getLastCID(), 7,
                        SVController.getCurrentView(), tomLayer.getSynchronizer().getLCManager().getLastReg(),
                        defaultSMMessage.getLeader());
                logger.info("Sending recovery state sender server info to {}", defaultSMMessage.getSender());
                tomLayer.getCommunication().send(new int[] { defaultSMMessage.getSender() }, response);
                logger.info("Recovery state sender server info sent");
                boolean iAmStateSender = defaultSMMessage.getStateSenderReplica() == SVController.getStaticConf().getProcessId();
                RecoveryBlindedStateSender recoveryStateSender = new RecoveryBlindedStateSender(SVController, appState,
                        defaultSMMessage.getServerPort(), confidentialityScheme, iAmStateSender, msg.getSender());
                recoveryStateSender.start();
            }
        } else {
            logger.warn("Received unknown SM message type from {}", msg.getSender());
        }
    }
    
    public void SMReplyDeliver(SMMessage msg, boolean isBFT) {
        try {
            lockTimer.lock();
            if (!SVController.getStaticConf().isStateTransferEnabled()) {
                return;
            }
            if (waitingCID == -1 || msg.getCID() != waitingCID) {
                logger.debug("I am not waiting for state or state contains different cid. WaitingCID: {} RequestCID: {}",
                        waitingCID, msg.getCID());
                return;
            }
            if (!appStateOnly) {
                senderRegencies.put(msg.getSender(), msg.getRegency());
                senderLeaders.put(msg.getSender(), msg.getLeader());
                senderViews.put(msg.getSender(), msg.getView());
            }
        } finally {
            lockTimer.unlock();
        }
    }
    
    public void onReconstructionCompleted(DefaultApplicationState recoveredState) {
        try {
            lockTimer.lock();
            int currentRegency;
            int currentLeader;
            View currentView;
            if (!appStateOnly) {
                Integer temp = getCurrentValue(senderRegencies);
                currentRegency = ((temp == null) ? -1 : temp);
                temp = getCurrentValue(senderLeaders);
                currentLeader = ((temp == null) ? -1 : temp);
                currentView = getCurrentValue(senderViews);
            }
            else {
                currentLeader = tomLayer.execManager.getCurrentLeader();
                currentRegency = tomLayer.getSynchronizer().getLCManager().getLastReg();
                currentView = SVController.getCurrentView();
            }
            if (currentRegency == -1 || currentLeader == -1 || currentView == null) {
                if (SVController.getCurrentViewN() - SVController.getCurrentViewF() <= getReplies()) {
                    logger.info("currentRegency or currentLeader or currentView are -1 or null");
                    if (stateTimer != null) {
                        stateTimer.cancel();
                    }
                    reset();
                    requestState();
                }
                else {
                    logger.info("Waiting for more than {} states", SVController.getQuorum());
                }
                return;
            }
            logger.info("More than f states confirmed");
            if (stateTimer != null) {
                stateTimer.cancel();
            }
            tomLayer.getSynchronizer().getLCManager().setLastReg(currentRegency);
            tomLayer.getSynchronizer().getLCManager().setNextReg(currentRegency);
            tomLayer.getSynchronizer().getLCManager().setNewLeader(currentLeader);
            tomLayer.execManager.setNewLeader(currentLeader);
            logger.info("currentRegency: {} currentLeader: {} currentViewId: {}", currentRegency, currentLeader,
                    currentView.getId());
            if (currentRegency > 0) {
                logger.debug("Removing STOP retransmissions up to regency {}", currentRegency);
                tomLayer.getSynchronizer().removeSTOPretransmissions(currentRegency - 1);
            }
            logger.info("Restoring state");
            state = recoveredState;
            if (state == null) {
                logger.error("Failed to reconstruct state. Retrying");
                reset();
                requestState();
                return;
            }
            logger.info("State reconstructed");
            dt.deliverLock();
            logger.info("Updating state");
            dt.update(state);
            logger.info("Last exec: {}", tomLayer.getLastExec());
            if (!appStateOnly && execManager.stopped()) {
                Queue<ConsensusMessage> stoppedMsgs = execManager.getStoppedMsgs();
                for (ConsensusMessage stopped : stoppedMsgs) {
                    if (stopped.getNumber() > state.getLastCID()) {
                        execManager.addOutOfContextMessage(stopped);
                    }
                }
                logger.debug("Clear Stopped");
                execManager.clearStopped();
                execManager.restart();
            }
            logger.debug("Processing out of context messages");
            tomLayer.processOutOfContext();
            logger.debug("Finished processing out of context messages");
            if (SVController.getCurrentViewId() != currentView.getId()) {
                logger.info("Installing current view!");
                SVController.reconfigureTo(currentView);
            }
            isInitializing = false;
            waitingCID = -1;
            dt.canDeliver();
            dt.deliverUnlock();
            reset();
            logger.info("I updated the state!");
            tomLayer.requestsTimer.clearAll();
            tomLayer.requestsTimer.Enabled(true);
            if (appStateOnly) {
                appStateOnly = false;
                tomLayer.getSynchronizer().resumeLC();
            }
        } finally {
            lockTimer.unlock();
            long recoveryEndTime = System.nanoTime();
            double totalTime = (recoveryEndTime - recoveryStartTime) / 1000000.0;
            logger.info("Recovery duration: {} ms", totalTime);
        }
    }
    
    private <T> T getCurrentValue(HashMap<Integer, T> senderValues) {
        Map<T, Integer> counter = new HashMap<>();
        for (T value : senderValues.values()) {
            counter.merge(value, 1, Integer::sum);
        }
        int max = 0;
        T result = null;
        for (Map.Entry<T, Integer> entry : counter.entrySet()) {
            if (entry.getValue() > max) {
                max = entry.getValue();
                result = entry.getKey();
            }
        }
        if (max <= SVController.getCurrentViewF()) {
            return null;
        }
        return result;
    }
}
