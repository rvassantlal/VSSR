package vssr;

import bftsmart.reconfiguration.views.View;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.secretsharing.Share;
import vssr.dprf.DPRFParameters;
import vssr.dprf.DPRFScheme;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public abstract class VSSRConfidentialityScheme {
    protected final Logger logger;
    protected final VSSFacade vss;
    private final Map<Integer, BigInteger> serverToShareholder;
    private final Map<BigInteger, Integer> shareholderToServer;
    private final Cipher cipher;
    private final boolean isLinearCommitmentScheme;
    protected KeysManager keysManager;
    protected DPRFScheme dprfScheme;
    protected DPRFParameters dprfParameters;
    protected final int f;
    private final Lock cipherLock;

    public VSSRConfidentialityScheme(View view) throws SecretSharingException {
        this.logger = LoggerFactory.getLogger("vssr");
        this.cipherLock = new ReentrantLock(true);
        int[] processes = view.getProcesses();
        this.serverToShareholder = new HashMap<>(processes.length);
        this.shareholderToServer = new HashMap<>(processes.length);
        BigInteger[] shareholders = new BigInteger[processes.length];
        for (int i = 0; i < processes.length; ++i) {
            int process = processes[i];
            BigInteger shareholder = BigInteger.valueOf(process + 1);
            this.serverToShareholder.put(process, shareholder);
            this.shareholderToServer.put(shareholder, process);
            shareholders[i] = shareholder;
        }
        int threshold = view.getF();
        this.f = threshold;
        Configuration configuration = Configuration.getInstance();
        Properties properties = new Properties();
        properties.put("threshold", String.valueOf(threshold));
        properties.put("dataEncAlgorithm", configuration.getDataEncryptionAlgorithm());
        properties.put("shareEncAlgorithm", configuration.getShareEncryptionAlgorithm());
        properties.put("commitmentScheme", configuration.getVssScheme());
        if (configuration.getVssScheme().equals("1")) {
            properties.put("p", configuration.getPrimeField());
            properties.put("q", configuration.getSubPrimeField());
            properties.put("g", configuration.getGenerator());
        }
        try {
            this.cipher = Cipher.getInstance(configuration.getShareEncryptionAlgorithm());
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SecretSharingException("Failed to initialize the cipher");
        }
        this.vss = new VSSFacade(properties, shareholders);
        this.keysManager = new KeysManager();
        this.isLinearCommitmentScheme = Configuration.getInstance().getVssScheme().equals("1");
        this.dprfScheme = new DPRFScheme(this.vss.getField(), new BigInteger(configuration.getGenerator(), 16));
        this.dprfParameters = this.dprfScheme.init(threshold, shareholders);
    }

    public boolean isLinearCommitmentScheme() {
        return this.isLinearCommitmentScheme;
    }

    public CommitmentScheme getCommitmentScheme() {
        return this.vss.getCommitmentScheme();
    }

    public BigInteger getShareholder( int process) {
        return this.serverToShareholder.get(process);
    }

    public int getProcess( BigInteger shareholder) {
        return this.shareholderToServer.get(shareholder);
    }

    public void updateParameters(View view) {
        throw new UnsupportedOperationException("Not implemented");
    }

    public byte[] encryptShareFor(int id, Share clearShare) throws SecretSharingException {
        Key encryptionKey = keysManager.getEncryptionKeyFor(id);
        try {
            return encrypt(clearShare.getShare().toByteArray(), encryptionKey);
        }
        catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SecretSharingException("Failed to encrypt share", e);
        }
    }

    public PublicKey getSigningPublicKeyFor(int id) {
        return this.keysManager.getSigningPublicKeyFor(id);
    }

    public PrivateKey getSigningPrivateKey() {
        return this.keysManager.getSigningKey();
    }

    public byte[] encryptDataFor(int id, byte[] data) {
        Key encryptionKey = this.keysManager.getEncryptionKeyFor(id);
        try {
            return this.encrypt(data, encryptionKey);
        }
        catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException ex) {
            return null;
        }
    }

    public BigInteger decryptShare(int id, byte[] encryptedShare) throws SecretSharingException {
        Key decryptionKey = this.keysManager.getDecryptionKeyFor(id);
        try {
            return new BigInteger(this.decrypt(encryptedShare, decryptionKey));
        }
        catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SecretSharingException("Failed to decrypt share", e);
        }
    }

    public byte[] decryptData(int id, byte[] encryptedData) {
        Key decryptionKey = this.keysManager.getDecryptionKeyFor(id);
        try {
            return this.decrypt(encryptedData, decryptionKey);
        }
        catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            return null;
        }
    }

    protected byte[] encrypt(byte[] data, Key encryptionKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        try {
            this.cipherLock.lock();
            this.cipher.init(1, encryptionKey);
            return this.cipher.doFinal(data);
        }
        finally {
            this.cipherLock.unlock();
        }
    }

    protected byte[] decrypt(byte[] data, Key decryptionKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        try {
            this.cipherLock.lock();
            this.cipher.init(2, decryptionKey);
            return this.cipher.doFinal(data);
        }
        finally {
            this.cipherLock.unlock();
        }
    }
}
