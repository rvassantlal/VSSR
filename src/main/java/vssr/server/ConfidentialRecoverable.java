package vssr.server;

import bftsmart.reconfiguration.ReconfigureRequest;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.StateManager;
import bftsmart.tom.MessageContext;
import bftsmart.tom.ReplicaContext;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.server.ProposeRequestVerifier;
import bftsmart.tom.server.Recoverable;
import bftsmart.tom.server.SingleExecutable;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentUtils;
import vss.commitment.constant.ConstantCommitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.VerifiableShare;
import vssr.*;
import vssr.encrypted.EncryptedConfidentialData;
import vssr.encrypted.EncryptedConfidentialMessage;
import vssr.encrypted.EncryptedShare;
import vssr.encrypted.EncryptedVerifiableShare;
import vssr.interServersCommunication.InterServersCommunication;
import vssr.statemanagement.ConfidentialSnapshot;
import vssr.statemanagement.ConfidentialStateLog;
import vssr.statemanagement.ConfidentialStateManager;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

public final class ConfidentialRecoverable implements SingleExecutable, Recoverable, ProposeRequestVerifier {
    private final Logger logger;
    private ServerConfidentialityScheme confidentialityScheme;
    private final int processId;
    private ReplicaContext replicaContext;
    private ConfidentialStateLog log;
    private ReentrantLock stateLock;
    private final ReentrantLock logLock;
    private ConfidentialStateManager stateManager;
    private InterServersCommunication interServersCommunication;
    private int checkpointPeriod;
    private final List<byte[]> commands;
    private final List<MessageContext> msgContexts;
    private int currentF;
    private final boolean useTLSEncryption;
    private final ConfidentialSingleExecutable confidentialExecutor;
    private boolean isLinearCommitmentScheme;
    private final Map<Integer, Request> deserializedRequests;
    private final boolean verifyClientsRequests;

    public ConfidentialRecoverable(int processId, ConfidentialSingleExecutable confidentialExecutor) {
        this.logger = LoggerFactory.getLogger("confidential");
        this.processId = processId;
        this.confidentialExecutor = confidentialExecutor;
        this.logLock = new ReentrantLock();
        this.commands = new ArrayList<>();
        this.msgContexts = new ArrayList<>();
        this.useTLSEncryption = Configuration.getInstance().useTLSEncryption();
        this.deserializedRequests = new ConcurrentHashMap<>();
        this.verifyClientsRequests = Configuration.getInstance().isVerifyClientRequests();
    }

    public void setReplicaContext(ReplicaContext replicaContext) {
        this.logger.debug("setting replica context");
        this.currentF = replicaContext.getSVController().getCurrentViewF();
        this.replicaContext = replicaContext;
        this.stateLock = new ReentrantLock();
        this.interServersCommunication = new InterServersCommunication(replicaContext.getServerCommunicationSystem(), replicaContext.getSVController());
        this.checkpointPeriod = replicaContext.getStaticConfiguration().getCheckpointPeriod();
        try {
            this.confidentialityScheme = new ServerConfidentialityScheme(this.processId, replicaContext.getCurrentView());
            this.isLinearCommitmentScheme = this.confidentialityScheme.isLinearCommitmentScheme();
            this.stateManager.setConfidentialityScheme(this.confidentialityScheme);
            this.log = this.getLog();
            this.stateManager.askCurrentConsensusId();
        }
        catch (SecretSharingException e) {
            this.logger.error("Failed to initialize ServerConfidentialityScheme", e);
        }
    }

    public boolean isValidRequest(TOMMessage request) {
        logger.debug("Checking request: {} - {}", request.getReqType(), request.getSequence());
        if (request.getMetadata() == null) {
            return true;
        }
        Metadata metadata = Metadata.getMessageType(request.getMetadata()[0]);
        logger.debug("Metadata: {}", metadata);
        if (metadata == Metadata.VERIFY) {
            if (!verifyClientsRequests) {
                return true;
            }
            Request req = preprocessRequest(request.getContent(), request.getPrivateContent(), request.getSender());
            if (req == null || req.getShares() == null) {
                return false;
            }
            deserializedRequests.put(hashRequest(request.getSender(), request.getSession(), request.getSequence()), req);
            for (ConfidentialData share : req.getShares()) {
                boolean isValid = confidentialityScheme.verify(share.getShare());
                if (!isValid) {
                    logger.warn("Client {} sent me an invalid share", request.getSender());
                    return false;
                }
            }
            return true;
        }
        else {
            if (metadata == Metadata.DOES_NOT_VERIFY) {
                return true;
            }
            logger.error("Unknown metadata {}", metadata);
            return false;
        }
    }

    private int hashRequest(int sender, int session, int sequence) {
        int hash = sender;
        hash = 31 * hash + session;
        hash = 31 * hash + sequence;
        return hash;
    }

    private ConfidentialStateLog getLog() {
        if (log == null) {
            log = initLog();
        }
        return log;
    }

    private ConfidentialStateLog initLog() {
        if (!replicaContext.getStaticConfiguration().isToLog()) {
            return null;
        }
        ConfidentialSnapshot snapshot = confidentialExecutor.getConfidentialSnapshot();
        byte[] state = snapshot.serialize();
        if (replicaContext.getStaticConfiguration().logToDisk()) {
            logger.error("Log to disk not implemented");
            return null;
        }
        logger.info("Logging to memory");
        return new ConfidentialStateLog(processId, checkpointPeriod, state, TOMUtil.computeHash(state));
    }

    public ApplicationState getState(int cid, boolean sendState) {
        logLock.lock();
        logger.debug("Getting state until CID {}", cid);
        ApplicationState state = (cid > -1) ? this.getLog().getApplicationState(cid, sendState) : new DefaultApplicationState();
        if (state == null || (replicaContext.getStaticConfiguration().isBFT() && state.getCertifiedDecision(replicaContext.getSVController()) == null)) {
            state = new DefaultApplicationState();
        }
        logLock.unlock();
        return state;
    }

    public int setState(ApplicationState recvState) {
        int lastCID = -1;
        if (recvState instanceof DefaultApplicationState) {
            DefaultApplicationState state = (DefaultApplicationState)recvState;
            logger.info("I'm going to update myself from CID {} to CID {}", state.getLastCheckpointCID(), state.getLastCID());
            stateLock.lock();
            logLock.lock();
            log.update(state);
            int lastCheckpointCID = log.getLastCheckpointCID();
            lastCID = this.log.getLastCID();
            if (state.getSerializedState() != null) {
                logger.info("Installing snapshot up to CID {}", lastCheckpointCID);
                ConfidentialSnapshot snapshot = ConfidentialSnapshot.deserialize(state.getSerializedState());
                confidentialExecutor.installConfidentialSnapshot(snapshot);
            }
            for (int cid = lastCheckpointCID + 1; cid <= lastCID; ++cid) {
                try {
                    logger.debug("Processing and verifying batched requests for CID {}", cid);
                    CommandsInfo cmdInfo = this.log.getMessageBatch(cid);
                    if (cmdInfo == null) {
                        logger.warn("Consensus {} is null", cid);
                    }
                    else {
                        byte[][] commands = cmdInfo.commands;
                        MessageContext[] msgCtx = cmdInfo.msgCtx;
                        if (commands != null && msgCtx != null && !msgCtx[0].isNoOp()) {
                            for (int i = 0; i < commands.length; ++i) {
                                Request request = Request.deserialize(commands[i]);
                                if (request == null) {
                                    logger.warn("Request is null");
                                }
                                else if (request.getType() == MessageType.APPLICATION) {
                                    logger.debug("Ignoring application request");
                                }
                                else {
                                    confidentialExecutor.appExecuteOrdered(request.getPlainData(), request.getShares(), msgCtx[i]);
                                }
                            }
                        }
                    }
                }
                catch (Exception e) {
                    logger.error("Failed to process and verify batched requests for CID {}", cid, e);
                    if (e instanceof ArrayIndexOutOfBoundsException) {
                        logger.info("Last checkpoint CID: {}", lastCheckpointCID);
                        logger.info("Last CID: {}", lastCID);
                        logger.info("Number of messages expected to be in the batch: {}", log.getLastCID() - log.getLastCheckpointCID() + 1);
                        logger.info("Number of messages in the batch: {}", log.getMessageBatches().length);
                    }
                }
            }
            logLock.unlock();
            stateLock.unlock();
        }
        return lastCID;
    }

    public StateManager getStateManager() {
        if (stateManager == null) {
            stateManager = new ConfidentialStateManager();
        }
        return stateManager;
    }

    public void Op(int CID, byte[] requests, MessageContext msgCtx) {
    }

    public void noOp(int CID, byte[][] operations, MessageContext[] msgCtx) {
        logger.debug("NoOp");
        for (byte[] operation : operations) {
            Object obj = TOMUtil.getObject(operation);
            if (obj instanceof ReconfigureRequest) {
                logger.info("Reconfiguration");
                ReconfigureRequest reconfigureRequest = (ReconfigureRequest)obj;
                for (int key : reconfigureRequest.getProperties().keySet()) {
                    String value = reconfigureRequest.getProperties().get(key);
                    if (key == 2) {
                        int f = Integer.parseInt(value);
                        if (currentF < f) {
                            logger.info("Increasing f. {}->{}", currentF, f);
                        }
                        else if (currentF > f) {
                            logger.info("Reducing f. {}->{}", currentF, f);
                        }
                        currentF = f;
                    }
                }
            }
        }
    }

    public byte[] executeOrdered(byte[] command, byte[] privateData, MessageContext msgCtx) {
        Request request;
        if (verifyClientsRequests) {
            int hash = hashRequest(msgCtx.getSender(), msgCtx.getSession(), msgCtx.getSequence());
            request = deserializedRequests.remove(hash);
            if (request == null) {
                request = preprocessRequest(command, privateData, msgCtx.getSender());
            }
        }
        else {
            request = preprocessRequest(command, privateData, msgCtx.getSender());
        }
        if (request == null) {
            return null;
        }
        byte[] preprocessedCommand = request.serialize();
        byte[] response;
        if (request.getType() == MessageType.APPLICATION) {
            logger.debug("Received application ordered message of {} in CID {}. Regency: {}", msgCtx.getSender(),
                    msgCtx.getConsensusId(), msgCtx.getRegency());
            interServersCommunication.messageReceived(request.getPlainData(), msgCtx);
            response = new byte[0];
        }
        else {
            stateLock.lock();
            ConfidentialMessage r = confidentialExecutor.appExecuteOrdered(request.getPlainData(), request.getShares(), msgCtx);
            response = (useTLSEncryption ? r.serialize() : encryptResponse(r, msgCtx).serialize());
            this.stateLock.unlock();
        }
        logRequest(preprocessedCommand, msgCtx);
        return response;
    }

    public byte[] executeUnordered(byte[] command, byte[] privateData, MessageContext msgCtx) {
        Request request = preprocessRequest(command, privateData, msgCtx.getSender());
        if (request == null) {
            return null;
        }
        if (request.getType() == MessageType.APPLICATION) {
            logger.debug("Received application unordered message of {} in CID {}", msgCtx.getSender(),
                    msgCtx.getConsensusId());
            interServersCommunication.messageReceived(request.getPlainData(), msgCtx);
            return new byte[0];
        }
        ConfidentialMessage r = confidentialExecutor.appExecuteUnordered(request.getPlainData(), request.getShares(), msgCtx);
        return useTLSEncryption ? r.serialize() : encryptResponse(r, msgCtx).serialize();
    }

    private EncryptedConfidentialMessage encryptResponse(ConfidentialMessage clearResponse, MessageContext msgCtx) {
        ConfidentialData[] clearShares = clearResponse.getShares();
        if (clearShares == null) {
            return new EncryptedConfidentialMessage(clearResponse.getPlainData());
        }
        EncryptedConfidentialData[] shares = new EncryptedConfidentialData[clearShares.length];
        for (int i = 0; i < clearShares.length; ++i) {
            ConfidentialData clearCD = clearShares[i];
            EncryptedVerifiableShare encryptedVS = encryptShare(msgCtx.getSender(), clearCD.getShare().getShareAtIndex(0));
            shares[i] = new EncryptedConfidentialData(encryptedVS);
        }
        return new EncryptedConfidentialMessage(clearResponse.getPlainData(), shares);
    }

    private EncryptedVerifiableShare encryptShare(int id, VerifiableShare clearShare) {
        try {
            byte[] encryptedShare = this.confidentialityScheme.encryptShareFor(id, clearShare.getShare());
            return new EncryptedVerifiableShare(clearShare.getShare().getShareholder(), encryptedShare,
                    clearShare.getCommitments(), clearShare.getSharedData());
        } catch (SecretSharingException e) {
            this.logger.error("Failed to encrypt share for client {}", id, e);
            return null;
        }
    }

    private Request preprocessRequest(byte[] commonData, byte[] privateData, int sender) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(commonData);
             ObjectInput in = new ObjectInputStream(bis)) {
            MessageType type = MessageType.getMessageType(in.read());
            Request result = null;
            byte[] plainData = null;
            switch (type) {
                case CLIENT: {
                    int len = in.readInt();
                    if (len != -1) {
                        plainData = new byte[len];
                        in.readFully(plainData);
                    }
                    len = in.readInt();
                    ConfidentialData[] shares = null;
                    if (len != -1) {
                        shares = new ConfidentialData[len];
                        if (len > 0) {
                            int rLen = in.readInt();
                            byte[] rBytes = new byte[rLen];
                            in.readFully(rBytes);
                            BigInteger r = new BigInteger(rBytes);
                            BigInteger shareholder = confidentialityScheme.getMyShareholderId();
                            ByteArrayInputStream privateBis = new ByteArrayInputStream(privateData);
                            try (ObjectInput privateIn = new ObjectInputStream(privateBis)) {
                                for (int i = 0; i < len; ++i) {
                                    int l = in.readInt();
                                    byte[] sharedData = null;
                                    if (l != -1) {
                                        sharedData = new byte[l];
                                        in.readFully(sharedData);
                                    }
                                    int nCommitments = in.readInt();
                                    Commitment[] commitments = new Commitment[nCommitments];
                                    EncryptedShare[][] encryptedShares = new EncryptedShare[nCommitments][1];
                                    for (int k = 0; k < commitments.length; ++k) {
                                        l = privateIn.readInt();
                                        byte[] encShare = null;
                                        if (l != -1) {
                                            encShare = new byte[l];
                                            privateIn.readFully(encShare);
                                        }
                                        if (isLinearCommitmentScheme) {
                                            commitments[k] = CommitmentUtils.getInstance().readCommitment(in);
                                        }
                                        else {
                                            byte[] c = new byte[in.readInt()];
                                            in.readFully(c);
                                            byte[] witness = new byte[privateIn.readInt()];
                                            privateIn.readFully(witness);
                                            TreeMap<Integer, byte[]> witnesses = new TreeMap<>();
                                            witnesses.put(shareholder.hashCode(), witness);
                                            commitments[k] = new ConstantCommitment(c, witnesses);
                                        }
                                        encryptedShares[k][0] = new EncryptedShare(shareholder, encShare);
                                    }
                                    VSSRPublishedShares publishedShares = new VSSRPublishedShares(r, encryptedShares, commitments, sharedData);
                                    VSSRShare vs = confidentialityScheme.extractShare(publishedShares);
                                    shares[i] = new ConfidentialData(vs);
                                }
                            }
                        }
                    }
                    result = new Request(type, plainData, shares);
                    break;
                }
                case APPLICATION: {
                    int len = in.readInt();
                    plainData = new byte[len];
                    in.readFully(plainData);
                    result = new Request(type, plainData);
                    break;
                }
            }
            return result;
        } catch (IOException | SecretSharingException | ClassNotFoundException e) {
            logger.warn("Failed to decompose request from {}", sender, e);
            return null;
        }
    }

    private void saveState(byte[] snapshot, int lastCID) {
        logLock.lock();
        logger.debug("Saving state of CID {}", lastCID);
        log.newCheckpoint(snapshot, TOMUtil.computeHash(snapshot), lastCID);
        logLock.unlock();
        logger.debug("Finished saving state of CID {}", lastCID);
    }

    private void saveCommands(byte[][] commands, MessageContext[] msgCtx) {
        if (commands.length != msgCtx.length) {
            logger.debug("----SIZE OF COMMANDS AND MESSAGE CONTEXTS IS DIFFERENT----");
            logger.debug("----COMMANDS: {}, CONTEXTS: {} ----", commands.length, msgCtx.length);
        }
        logger.debug("Saving Commands of client {} with cid {}", msgCtx[0].getSender(), msgCtx[0].getConsensusId());
        logLock.lock();
        int cid = msgCtx[0].getConsensusId();
        int batchStart = 0;
        for (int i = 0; i <= msgCtx.length; ++i) {
            if (i == msgCtx.length) {
                byte[][] batch = Arrays.copyOfRange(commands, batchStart, i);
                MessageContext[] batchMsgCtx = Arrays.copyOfRange(msgCtx, batchStart, i);
                log.addMessageBatch(batch, batchMsgCtx, cid);
            }
            else if (msgCtx[i].getConsensusId() > cid) {
                byte[][] batch = Arrays.copyOfRange(commands, batchStart, i);
                MessageContext[] batchMsgCtx = Arrays.copyOfRange(msgCtx, batchStart, i);
                log.addMessageBatch(batch, batchMsgCtx, cid);
                cid = msgCtx[i].getConsensusId();
                batchStart = i;
            }
        }
        logger.debug("Log size: " + log.getNumBatches());
        logLock.unlock();
    }

    private void logRequest(byte[] command, MessageContext msgCtx) {
        int cid = msgCtx.getConsensusId();
        commands.add(command);
        msgContexts.add(msgCtx);
        if (!msgCtx.isLastInBatch()) {
            return;
        }
        if (cid > 0 && cid % checkpointPeriod == 0) {
            logger.info("Performing checkpoint for consensus " + cid);
            stateLock.lock();
            ConfidentialSnapshot snapshot = confidentialExecutor.getConfidentialSnapshot();
            stateLock.unlock();
            saveState(snapshot.serialize(), cid);
        }
        else {
            saveCommands(commands.toArray(new byte[0][]), msgContexts.toArray(new MessageContext[0]));
        }
        getStateManager().setLastCID(cid);
        commands.clear();
        msgContexts.clear();
    }
}
