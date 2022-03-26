package vssr.client;

import bftsmart.reconfiguration.views.View;
import vss.commitment.Commitment;
import vss.facade.Mode;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vssr.VSSRConfidentialityScheme;
import vssr.VSSRPublishedShares;
import vssr.dprf.DPRFContribution;
import vssr.dprf.DPRFPrivateParameters;
import vssr.encrypted.EncryptedShare;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;

public class ClientConfidentialityScheme extends VSSRConfidentialityScheme {
	private final int[] servers;
	private final int l;
	private final MessageDigest messageDigest;

	public ClientConfidentialityScheme(View view) throws SecretSharingException {
		super(view);
		int[] currentViewProcesses = view.getProcesses();
		int n = view.getN();
		this.servers = currentViewProcesses;
		this.l = (int)Math.ceil(n / (double)this.f);
		try {
			this.messageDigest = MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e) {
			throw new SecretSharingException("Failed to initialize message digest", e);
		}
	}

	public VSSRPublishedShares share(byte[] secret) throws SecretSharingException {
		BigInteger r = dprfScheme.getRandomNumber();
		BigInteger[] yi = new BigInteger[servers.length];
		for (int i = 0; i < servers.length; ++i) {
			BigInteger shareholder = getShareholder(servers[i]);
			DPRFContribution[] contributes = new DPRFContribution[servers.length];
			for (int j = 0; j < servers.length; ++j) {
				BigInteger s = getShareholder(servers[j]);
				DPRFPrivateParameters privateParameters = dprfParameters.getPrivateParameterOf(s);
				contributes[j] = dprfScheme.contribute(s, privateParameters, r, shareholder);
			}
			yi[i] = dprfScheme.evaluate(dprfParameters.getPublicParameters(), shareholder, contributes).mod(vss.getField());
		}
		Commitment[] commitments = new Commitment[l + 1];
		EncryptedShare[][] encryptedShares = new EncryptedShare[l + 1][];
		for (int k = 1; k <= l; ++k) {
			LinkedList<Share> shares = new LinkedList<>();
			for (int min = Math.min(k * f, yi.length), l = (k - 1) * f; l < min; ++l) {
				shares.add(new Share(getShareholder(servers[l]), yi[l]));
			}
			if (shares.size() <= f) {
				int x = f + 1 - shares.size();
				while (x-- > 0) {
					BigInteger rndNumb = dprfScheme.getRandomNumber();
					shares.add(new Share(rndNumb, rndNumb));
				}
			}
			OpenPublishedShares recoveryShares = shareRecoveryPoint(shares.toArray(new Share[0]));
			commitments[k] = recoveryShares.getCommitments();
			encryptedShares[k] = encryptShares(recoveryShares.getShares());
		}

		OpenPublishedShares secretShare = vss.share(secret, Mode.LARGE_SECRET, f);
		commitments[0] = secretShare.getCommitments();
		encryptedShares[0] = encryptShares(secretShare.getShares());
		return new VSSRPublishedShares(r, encryptedShares, commitments, secretShare.getSharedData());
	}

	private EncryptedShare[] encryptShares(Share[] shares) throws SecretSharingException {
		EncryptedShare[] result = new EncryptedShare[shares.length];
		for (int i = 0; i < shares.length; i++) {
			Share share = shares[i];
			byte[] es = encryptShareFor(getProcess(share.getShareholder()), share);
			result[i] = new EncryptedShare(share.getShareholder(), es);
		}
		return result;
	}

	private OpenPublishedShares shareRecoveryPoint(Share[] shares) throws SecretSharingException {
		Share[] resultingShares = new Share[servers.length];
		Polynomial polynomial = new Polynomial(vss.getField(), shares);
		for (int i = 0; i < servers.length; ++i) {
			BigInteger shareholder = getShareholder(servers[i]);
			resultingShares[i] = new Share(shareholder, polynomial.evaluateAt(shareholder));
		}
		Commitment commitment = vss.getCommitmentScheme().generateCommitments(polynomial);
		return new OpenPublishedShares(resultingShares, commitment, null);
	}

	public byte[] combine(OpenPublishedShares shares) throws SecretSharingException {
		Share[] s = shares.getShares();
		vss.getCommitmentScheme().startVerification(shares.getCommitments());
		for (Share share : s) {
			if (!vss.getCommitmentScheme().checkValidity(share, shares.getCommitments())) {
				vss.getCommitmentScheme().endVerification();
				return null;
			}
		}
		vss.getCommitmentScheme().endVerification();
		Polynomial p = new Polynomial(vss.getField(), s);
		BigInteger secretKeyAsNumber = p.getConstant();
		byte[] keyBytes = messageDigest.digest(secretKeyAsNumber.toByteArray());
		SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
		try {
			return decrypt(shares.getSharedData(), secretKey);
		} catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
			throw new SecretSharingException("Error while decrypting secret!", e);
		}
	}
}
