package vssr.statemanagement.privatestate.sender;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentUtils;
import vssr.Configuration;
import vssr.RecoveryContribution;
import vssr.statemanagement.utils.HashThread;

import javax.net.SocketFactory;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class BlindedDataSender extends Thread {
    private final Logger logger;
    private final int pid;
    private final String receiverServersIp;
    private final int receiverServerPort;
    private final boolean iAmStateSender;
    private Socket connection;
    private final Lock lock;
    private final Condition waitingSharesCondition;
    private final Condition waitingCommonStateCondition;
    private BlindedShares blindedShares;
    private byte[] commonState;
    private byte[] commonStateHash;

    public BlindedDataSender(int pid, String receiverServersIp, int receiverServerPort, boolean iAmStateSender) {
        super("Blinded Data Sender Thread for " + receiverServersIp + ":" + receiverServerPort);
        this.logger = LoggerFactory.getLogger("state_transfer");
        this.pid = pid;
        this.receiverServersIp = receiverServersIp;
        this.receiverServerPort = receiverServerPort;
        this.iAmStateSender = iAmStateSender;
        this.lock = new ReentrantLock(true);
        this.waitingSharesCondition = this.lock.newCondition();
        this.waitingCommonStateCondition = this.lock.newCondition();
    }

    public void setBlindedShares(BlindedShares blindedShares) {
        this.lock.lock();
        this.blindedShares = blindedShares;
        this.waitingSharesCondition.signal();
        this.lock.unlock();
    }

    public void setCommonState(byte[] commonState, byte[] commonStateHash) {
        this.lock.lock();
        this.commonState = commonState;
        this.commonStateHash = commonStateHash;
        this.waitingCommonStateCondition.signal();
        this.lock.unlock();
    }

    @Override
    public void run() {
        boolean usingLinearScheme = Configuration.getInstance().getVssScheme().equals("1");
        try {
            lock.lock();
            if (commonState == null && commonStateHash == null) {
                waitingCommonStateCondition.await();
            }
            lock.unlock();
            logger.debug("Connecting to {}:{}", receiverServersIp, receiverServerPort);
            connection = SocketFactory.getDefault().createSocket(receiverServersIp, receiverServerPort);

            try (ObjectOutput out = new ObjectOutputStream(connection.getOutputStream())) {
                connection.setKeepAlive(true);
                connection.setTcpNoDelay(true);
                out.writeInt(pid);
                if (iAmStateSender) {
                    logger.info("Sending {} bytes of common state", commonState.length);
                    out.write(0);
                    out.writeInt(commonState.length);
                    out.write(commonState);
                } else {
                    logger.debug("Sending common state hash");
                    out.write(1);
                    out.writeInt(commonStateHash.length);
                    out.write(commonStateHash);
                }
                out.flush();
                logger.debug("Sent common state");
                lock.lock();
                if (blindedShares == null) {
                    waitingSharesCondition.await();
                }
                lock.unlock();
                logger.debug("Received blinded shares");
                RecoveryContribution[] contributions = blindedShares.getContributions();
                out.writeInt(contributions.length);
                HashThread commitmentsHashThread = null;
                Commitment[] commitments = blindedShares.getCommitment();
                if (usingLinearScheme) {
                    if (iAmStateSender) {
                        logger.info("Sending {} commitments", commitments.length);
                        out.write(0);
                        out.writeInt(commitments.length);
                        for (Commitment commitment : commitments) {
                            CommitmentUtils.getInstance().writeCommitment(commitment, out);
                        }
                        for (RecoveryContribution contribution : contributions) {
                            byte[] r = contribution.getR().toByteArray();
                            out.writeInt(r.length);
                            out.write(r);
                        }
                        out.flush();
                    } else {
                        out.write(1);
                        int totalCommitmentsArraySize = 4 * commitments.length;
                        byte[] commitmentsHashArray = new byte[totalCommitmentsArraySize + 4 * contributions.length];
                        commitmentsHashThread = new HashThread();
                        commitmentsHashThread.setData(commitmentsHashArray);
                        commitmentsHashThread.start();
                        int index = 0;
                        for (Commitment commitment : commitments) {
                            byte[] bytes = vssr.Utils.toBytes(commitment.consistentHash());
                            for (final byte value : bytes) {
                                commitmentsHashArray[index++] = value;
                            }
                            commitmentsHashThread.update(index - 4, 4);
                        }
                        for (RecoveryContribution contribution : contributions) {
                            BigInteger r = contribution.getR();
                            byte[] bytes = vssr.Utils.toBytes(r.hashCode());
                            for (byte value : bytes) {
                                commitmentsHashArray[index++] = value;
                            }
                            commitmentsHashThread.update(index - 4, 4);
                        }
                    }
                } else {
                    logger.info("Sending {} commitments", commitments.length);
                    out.writeInt(commitments.length);
                    for (Commitment commitment : commitments) {
                        CommitmentUtils.getInstance().writeCommitment(commitment, out);
                    }
                    for (RecoveryContribution contribution : contributions) {
                        byte[] r = contribution.getR().toByteArray();
                        out.writeInt(r.length);
                        out.write(r);
                    }
                    out.flush();
                }
                byte[][] shares = this.blindedShares.getShare();
                logger.info("Sending {} blinded shares", shares.length);
                out.writeInt(shares.length);
                for (byte[] blindedShare : shares) {
                    out.writeInt(blindedShare.length);
                    out.write(blindedShare);
                }
                for (RecoveryContribution contribution : contributions) {
                    contribution.getDPRFContribution().writeExternal(out);
                }
                out.flush();
                if (usingLinearScheme && commitmentsHashThread != null) {
                    logger.debug("Sending commitments hash");
                    commitmentsHashThread.update(-1, -1);
                    byte[] commitmentsHash = commitmentsHashThread.getHash();
                    out.writeInt(commitmentsHash.length);
                    out.write(commitmentsHash);
                }
                out.flush();
            } catch (SocketException | InterruptedException ignored) {
            } catch (IOException | NoSuchAlgorithmException e) {
                logger.error("Failed to send data to {}:{}", receiverServersIp, receiverServerPort, e);
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        this.logger.debug("Exiting blinded data sender for {}:{}", receiverServersIp, receiverServerPort);
    }
}
