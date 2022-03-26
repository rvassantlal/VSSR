package vssr.statemanagement.utils;

import bftsmart.tom.util.TOMUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingDeque;

public class HashThread extends Thread {
    private final Logger logger;
    private final MessageDigest digest;
    private final CountDownLatch latch;
    private final BlockingQueue<Pair> offsets;
    private byte[] data;
    private byte[] result;

    public HashThread() throws NoSuchAlgorithmException {
        super("Hash Thread");
        this.logger = LoggerFactory.getLogger("confidential");
        this.digest = TOMUtil.getHashEngine();
        this.latch = new CountDownLatch(1);
        this.offsets = new LinkedBlockingDeque<>();
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public byte[] getHash() {
        try {
            latch.await();
            return this.result;
        } catch (InterruptedException e) {
            logger.error("Failed to wait for digest result", e);
            return null;
        }
    }

    public void update(int offset, int len) {
        try {
            offsets.put(new Pair(offset, len));
        } catch (InterruptedException e) {
            logger.error("Failed to add offset to queue.", e);
        }
    }

    @Override
    public void run() {
        while (true) {
            try {
                while (true) {
                    Pair offset = offsets.take();
                    if (offset.offset == -1) {
                        break;
                    }
                    digest.update(data, offset.offset, offset.len);
                }
            } catch (InterruptedException e) {
                logger.error("Failed to take offset from queue.", e);
                continue;
            }
            break;
        }
        result = digest.digest();
        latch.countDown();
        logger.debug("Exiting Hash Thread");
    }

    private static class Pair {
        private final int offset;
        private final int len;

        Pair(int offset, int len) {
            this.offset = offset;
            this.len = len;
        }
    }
}
