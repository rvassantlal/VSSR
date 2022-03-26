package vssr.server;

import bftsmart.reconfiguration.views.View;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;
import vssr.RecoveryContribution;
import vssr.VSSRConfidentialityScheme;
import vssr.VSSRPublishedShares;
import vssr.VSSRShare;
import vssr.dprf.DPRFContribution;
import vssr.dprf.DPRFPrivateParameters;
import vssr.encrypted.EncryptedShare;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class ServerConfidentialityScheme extends VSSRConfidentialityScheme {
    private final Key decipheringKey;
    private final BigInteger me;
    private final Lock shareEncryptionLock;
    
    public ServerConfidentialityScheme(int processId, View view) throws SecretSharingException {
        super(view);
        this.decipheringKey = keysManager.getDecryptionKeyFor(processId);
        this.me = this.getShareholder(processId);
        this.shareEncryptionLock = new ReentrantLock(true);
    }
    
    public boolean verify(VSSRShare share) {
        VerifiableShare[] verifiableShares = share.getVerifiableShares();
        for (VerifiableShare verifiableShare : verifiableShares) {
            if (verifiableShare != null) {
                if (!vss.getCommitmentScheme().checkValidityWithoutPreComputation(verifiableShare.getShare(), verifiableShare.getCommitments())) {
                    System.out.println(verifiableShare);
                    return false;
                }
            }
        }
        return true;
    }
    
    public VSSRShare extractShare(VSSRPublishedShares privateShares) throws SecretSharingException {
        EncryptedShare[] encryptedShares = privateShares.getShareOf(me);
        if (encryptedShares == null) {
            throw new SecretSharingException("Share not found");
        }
        try {
            VerifiableShare[] verifiableShares = new VerifiableShare[encryptedShares.length];
            for (int i = 0; i < encryptedShares.length; ++i) {
                EncryptedShare encryptedShare = encryptedShares[i];
                shareEncryptionLock.lock();
                BigInteger decryptedShare = new BigInteger(decrypt(encryptedShare.getEncryptedShare(), decipheringKey));
                shareEncryptionLock.unlock();
                Share share = new Share(encryptedShare.getShareholder(), decryptedShare);
                Commitment commitment = vss.getCommitmentScheme().extractCommitment(share.getShareholder(), privateShares.getCommitments()[i]);
                verifiableShares[i] = new VerifiableShare(share, commitment, (i == 0) ? privateShares.getSharedData() : null);
            }
            return new VSSRShare(privateShares.getR(), verifiableShares);
        }
        catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            throw new SecretSharingException("Error while decrypting share!", e);
        }
    }
    
    public RecoveryContribution recoveryContribution(VSSRShare share, BigInteger recoveringShareholder) {
        DPRFPrivateParameters privateParameters = dprfParameters.getPrivateParameterOf(me);
        DPRFContribution contribute = dprfScheme.contribute(me, privateParameters, share.getR(), recoveringShareholder);
        int j = (int)Math.ceil(getProcess(recoveringShareholder) / (double)f) + 1;
        BigInteger recoveringShare = share.getShareAtIndex(0).getShare().getShare().add(share.getShareAtIndex(j).getShare().getShare()).mod(vss.getField());
        Commitment shareCommitment = share.getShareAtIndex(0).getCommitments();
        Commitment recoveringCommitment = share.getShareAtIndex(j).getCommitments();
        return new RecoveryContribution(share.getR(), me, contribute, recoveringShare, shareCommitment, recoveringCommitment, share.getShareAtIndex(0).getSharedData());
    }
    
    public VSSRShare recoverShare(final RecoveryContribution[] recoveryContribution) throws SecretSharingException {
        Share[] recoveryShares = new Share[recoveryContribution.length];
        DPRFContribution[] dprfContributions = new DPRFContribution[recoveryContribution.length];
        Map<BigInteger, Commitment> allCommitments = new HashMap<>(recoveryContribution.length);
        byte[] sharedData = null;
        BigInteger r = null;
        for (int i = 0; i < recoveryContribution.length; ++i) {
            RecoveryContribution contribution = recoveryContribution[i];
            Commitment recoveryCommitment = vss.getCommitmentScheme().sumCommitments(contribution.getShareCommitment(), contribution.getRecoveringCommitment());
            recoveryShares[i] = new Share(contribution.getShareholder(), contribution.getRecoveringShare());
            if (!vss.getCommitmentScheme().checkValidityWithoutPreComputation(recoveryShares[i], recoveryCommitment)) {
                throw new SecretSharingException("Recovery commitment is invalid");
            }
            dprfContributions[i] = contribution.getDPRFContribution();
            allCommitments.put(contribution.getShareholder(), contribution.getShareCommitment());
            if (sharedData == null) {
                sharedData = contribution.getSharedData();
            }
            else if (!Arrays.equals(sharedData, contribution.getSharedData())) {
                throw new SecretSharingException("Shared data are different");
            }
            if (r == null) {
                r = contribution.getR();
            }
            else if (!r.equals(contribution.getR())) {
                throw new SecretSharingException("Different r value");
            }
        }
        Commitment recoveredCommitment = vss.getCommitmentScheme().recoverCommitment(me, allCommitments);
        BigInteger s = new Polynomial(getField(), recoveryShares).evaluateAt(me);
        BigInteger y = dprfScheme.evaluate(dprfParameters.getPublicParameters(), me, dprfContributions);
        Share recoveredShare = new Share(me, s.subtract(y).mod(getField()));
        if (!vss.getCommitmentScheme().checkValidityWithoutPreComputation(recoveredShare, recoveredCommitment)) {
            StringBuilder sb = new StringBuilder();
            for (RecoveryContribution contribution : recoveryContribution) {
                sb.append(contribution.toString());
                sb.append("\n");
            }
            logger.error("Recovered share is invalid.\n{}\n", sb);
            System.exit(-1);
            return null;
        }
        VerifiableShare vs = new VerifiableShare(recoveredShare, recoveredCommitment, sharedData);
        return new VSSRShare(r, new VerifiableShare[] { vs, null, null, null });
    }
    
    @Override
    public CommitmentScheme getCommitmentScheme() {
        return vss.getCommitmentScheme();
    }
    
    public InterpolationStrategy getInterpolationStrategy() {
        return vss.getInterpolationStrategy();
    }
    
    public BigInteger getField() {
        return vss.getField();
    }
    
    public BigInteger getMyShareholderId() {
        return me;
    }
}
