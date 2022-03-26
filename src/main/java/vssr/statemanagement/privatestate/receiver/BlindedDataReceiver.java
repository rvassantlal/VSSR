package vssr.statemanagement.privatestate.receiver;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.reconfiguration.views.View;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentUtils;
import vssr.Configuration;
import vssr.RecoveryContribution;
import vssr.dprf.DPRFContribution;
import vssr.statemanagement.utils.HashThread;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

public class BlindedDataReceiver extends Thread {
    private final Logger logger;
    private final BlindedStateHandler blindedStateHandler;
    private final Set<String> knownServerIps;
    private final ServerViewController svController;
    private final int serverPort;
    private final int quorum;
    private final int stateSenderReplica;

    public BlindedDataReceiver(BlindedStateHandler blindedStateHandler, ServerViewController svController,
                               int serverPort, int quorum, int stateSenderReplica) throws IOException {
        super("Blinded Data Receiver Thread");
        this.logger = LoggerFactory.getLogger("state_transfer");
        this.blindedStateHandler = blindedStateHandler;
        this.svController = svController;
        this.serverPort = serverPort;
        this.quorum = quorum;
        this.stateSenderReplica = stateSenderReplica;
        View currentView = svController.getCurrentView();
        this.knownServerIps = new HashSet<>(currentView.getN());
        for (int process : currentView.getProcesses()) {
            String ip = currentView.getAddress(process).getAddress().getHostAddress();
            knownServerIps.add(ip);
        }
    }

    @Override
    public void run() {
        boolean usingLinearScheme = Configuration.getInstance().getVssScheme().equals("1");
        try {
            ServerSocket serverSocket = new ServerSocket();
            try {
                String myIp = svController.getStaticConf().getLocalAddress(svController.getStaticConf()
                        .getProcessId()).getAddress().getHostAddress();
                serverSocket.bind(new InetSocketAddress(myIp, serverPort));
                logger.debug("Listening for blinded data on {}:{}", serverSocket.getInetAddress().getHostAddress(),
                        serverSocket.getLocalPort());
                int nReceivedStates = 0;
                boolean receivedFullState = false;
                while (true) {
                    if (nReceivedStates >= this.quorum) {
                        if (receivedFullState) {
                            break;
                        }
                    }
                    try (Socket client = serverSocket.accept()) {
                        try (ObjectInput in = new ObjectInputStream(client.getInputStream())) {
                            client.setKeepAlive(true);
                            client.setTcpNoDelay(true);
                            String clientIp = client.getInetAddress().getHostAddress();
                            if (!knownServerIps.contains(clientIp)) {
                                logger.debug("Received connection from unknown server with ip {}", clientIp);
                                continue;
                            }
                            long elapsedTotal = 0L;
                            long elapsedCommonState = 0L;
                            long elapsedCommitments = 0L;
                            long elapsedBlindedShares = 0L;
                            byte[] commonState = null;
                            byte[] commonStateHash = null;
                            Commitment[] commitments = null;
                            byte[] commitmentsHash = null;
                            BigInteger[] rs = null;
                            long t1Total = System.nanoTime();
                            int pid = in.readInt();
                            long t2Total = System.nanoTime();
                            elapsedTotal += t2Total - t1Total;
                            logger.debug("Going to receive blinded data from {}", pid);
                            HashThread commonStateHashThread = null;
                            byte flag = (byte) in.read();
                            int size = in.readInt();
                            if (flag == 0) {
                                logger.debug("Going to receive {} bytes of common state", size);
                                commonState = new byte[size];
                                commonStateHashThread = new HashThread();
                                commonStateHashThread.setData(commonState);
                                commonStateHashThread.start();
                                int received;
                                for (int i = 0; i < size; i += received) {
                                    long t1CommonState = System.nanoTime();
                                    received = in.read(commonState, i, size - i);
                                    long t2CommonState = System.nanoTime();
                                    elapsedCommonState += t2CommonState - t1CommonState;
                                    if (received > -1) {
                                        commonStateHashThread.update(i, received);
                                    }
                                }
                                logger.debug("Received common state from {}", pid);
                                commonStateHashThread.update(-1, -1);
                            } else {
                                logger.debug("Going to receive common state hash");
                                commonStateHash = new byte[size];
                                long t1CommonState = System.nanoTime();
                                in.readFully(commonStateHash);
                                long t2CommonState = System.nanoTime();
                                elapsedCommonState += t2CommonState - t1CommonState;
                            }
                            int nContributions = in.readInt();
                            RecoveryContribution[] contributions = new RecoveryContribution[nContributions];
                            for (int j = 0; j < contributions.length; ++j) {
                                contributions[j] = new RecoveryContribution();
                            }
                            HashThread commitmentsHashThread = null;
                            if (usingLinearScheme) {
                                flag = (byte) in.read();
                                if (flag == 0) {
                                    long t1Commitments = System.nanoTime();
                                    int nCommitments = in.readInt();
                                    long t2Commitments = System.nanoTime();
                                    elapsedCommitments += t2Commitments - t1Commitments;
                                    logger.debug("Going to receive {} commitments from {}", nCommitments, pid);
                                    commitments = new Commitment[nCommitments];
                                    int totalCommitmentsArraySize = 4 * nCommitments;
                                    byte[] commitmentsHashArray = new byte[totalCommitmentsArraySize + 4 * nContributions];
                                    commitmentsHashThread = new HashThread();
                                    commitmentsHashThread.setData(commitmentsHashArray);
                                    commitmentsHashThread.start();
                                    int index = 0;
                                    for (int k = 0; k < nCommitments; ++k) {
                                        t1Commitments = System.nanoTime();
                                        commitments[k] = CommitmentUtils.getInstance().readCommitment(in);
                                        t2Commitments = System.nanoTime();
                                        elapsedCommitments += t2Commitments - t1Commitments;
                                        byte[] bytes = vssr.Utils.toBytes(commitments[k].consistentHash());
                                        for (byte value : bytes) {
                                            commitmentsHashArray[index++] = value;
                                        }
                                        commitmentsHashThread.update(index - 4, 4);
                                    }
                                    rs = new BigInteger[nContributions];
                                    for (int l = 0; l < nContributions; ++l) {
                                        t1Commitments = System.nanoTime();
                                        byte[] r = new byte[in.readInt()];
                                        in.readFully(r);
                                        t2Commitments = System.nanoTime();
                                        elapsedCommitments += t2Commitments - t1Commitments;
                                        BigInteger big = new BigInteger(r);
                                        rs[l] = big;
                                        byte[] bytes = vssr.Utils.toBytes(big.hashCode());
                                        for (byte value2 : bytes) {
                                            commitmentsHashArray[index++] = value2;
                                        }
                                        commitmentsHashThread.update(index - 4, 4);
                                    }
                                    commitmentsHashThread.update(-1, -1);
                                }
                            } else {
                                long t1Commitments = System.nanoTime();
                                int nCommitments = in.readInt();
                                long t2Commitments = System.nanoTime();
                                elapsedCommitments += t2Commitments - t1Commitments;
                                commitments = new Commitment[nCommitments];
                                for (int m = 0; m < nCommitments; ++m) {
                                    t1Commitments = System.nanoTime();
                                    commitments[m] = CommitmentUtils.getInstance().readCommitment(in);
                                    t2Commitments = System.nanoTime();
                                    elapsedCommitments += t2Commitments - t1Commitments;
                                }
                                rs = new BigInteger[nContributions];
                                for (int i2 = 0; i2 < nContributions; ++i2) {
                                    t1Commitments = System.nanoTime();
                                    byte[] r2 = new byte[in.readInt()];
                                    in.readFully(r2);
                                    t2Commitments = System.nanoTime();
                                    elapsedCommitments += t2Commitments - t1Commitments;
                                    rs[i2] = new BigInteger(r2);
                                }
                            }
                            int nShares = in.readInt();
                            logger.debug("Going to receive {} shares from {}", nShares, pid);
                            byte[][] shares = new byte[nShares][];
                            for (int i2 = 0; i2 < nShares; ++i2) {
                                size = in.readInt();
                                byte[] b2 = new byte[size];
                                long t1BlindedShares = System.nanoTime();
                                in.readFully(b2);
                                long t2BlindedShares = System.nanoTime();
                                elapsedBlindedShares += t2BlindedShares - t1BlindedShares;
                                shares[i2] = b2;
                            }
                            for (int i2 = 0; i2 < nContributions; ++i2) {
                                DPRFContribution dprfContribution = new DPRFContribution();
                                long t1BlindedShares = System.nanoTime();
                                dprfContribution.readExternal(in);
                                long t2BlindedShares = System.nanoTime();
                                elapsedBlindedShares += t2BlindedShares - t1BlindedShares;
                                contributions[i2].setDPRFContribution(dprfContribution);
                            }
                            logger.debug("Received blinded state from {}", pid);
                            if (commitments == null) {
                                long t1Commitments = System.nanoTime();
                                size = in.readInt();
                                long t2Commitments = System.nanoTime();
                                elapsedCommitments += t2Commitments - t1Commitments;
                                commitmentsHash = new byte[size];
                                t1Commitments = System.nanoTime();
                                in.readFully(commitmentsHash);
                                t2Commitments = System.nanoTime();
                                elapsedCommitments += t2Commitments - t1Commitments;
                            } else if (commitmentsHashThread != null) {
                                commitmentsHash = commitmentsHashThread.getHash();
                            }
                            if (commonStateHashThread != null) {
                                commonStateHash = commonStateHashThread.getHash();
                            }
                            elapsedTotal += elapsedCommonState + elapsedCommitments + elapsedBlindedShares;
                            logger.info("Took {} ms to receive common state from {}", elapsedCommonState / 1000000.0, pid);
                            logger.info("Took {} ms to receive commitments from {}", elapsedCommitments / 1000000.0, pid);
                            logger.info("Took {} ms to receive blinded shares from {}", elapsedBlindedShares / 1000000.0, pid);
                            logger.info("Took {} ms to receive state from {} (total)", elapsedTotal / 1000000.0, pid);
                            blindedStateHandler.deliverBlindedData(pid, shares, commonState, commonStateHash,
                                    commitments, commitmentsHash, rs, contributions);
                            if (pid == stateSenderReplica) {
                                receivedFullState = true;
                            }
                            nReceivedStates++;
                        }
                    } catch (NoSuchAlgorithmException e) {
                        logger.error("Failed to create hash thread.", e);
                    } catch (ClassNotFoundException e) {
                        logger.error("Failed to read commitments.", e);
                    } catch (IOException e) {
                        this.logger.error("Failed to receive data", e);
                    }
                }
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        catch (IOException e) {
            this.logger.error("Failed to initialize server socket.", e);
        }
        this.logger.debug("Exiting blinded data receiver thread");
    }
}
