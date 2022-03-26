package vssr.encrypted;

import vss.commitment.Commitment;
import vss.commitment.CommitmentUtils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;


/**
 *
 * @author Robin
 */
public class PrivatePublishedShares implements Externalizable {
	private EncryptedShare[] encryptedShares;
	private Commitment commitments;
	private byte[] sharedData;

	public PrivatePublishedShares() {}

	PrivatePublishedShares(EncryptedShare[] encryptedShares, Commitment commitments, byte[] sharedData) {
		this.encryptedShares = encryptedShares;
		this.commitments = commitments;
		this.sharedData = sharedData;
	}

	public EncryptedShare[] getEncryptedShares() {
		return encryptedShares;
	}

	public Commitment getCommitments() {
		return commitments;
	}

	public byte[] getSharedData() {
		return sharedData;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(encryptedShares == null ? -1 : encryptedShares.length);
		if (encryptedShares != null) {
			for (EncryptedShare encryptedShare : encryptedShares)
				encryptedShare.writeExternal(out);
		}
		CommitmentUtils.getInstance().writeCommitment(commitments, out);
		out.writeInt(sharedData == null ? -1 : sharedData.length);
		if (sharedData != null)
			out.write(sharedData);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		int len = in.readInt();
		if (len != -1) {
			encryptedShares = new EncryptedShare[len];
			EncryptedShare encryptedShare;
			for (int i = 0; i < len; i++) {
				encryptedShare = new EncryptedShare();
				encryptedShare.readExternal(in);
				encryptedShares[i] = encryptedShare;
			}
		}
		commitments = CommitmentUtils.getInstance().readCommitment(in);
		len = in.readInt();
		if (len != -1) {
			sharedData = new byte[len];
			in.readFully(sharedData);
		}

	}

	public EncryptedShare getShareOf(BigInteger shareholder) {
		for (EncryptedShare encryptedShare : encryptedShares) {
			if (encryptedShare.getShareholder().equals(shareholder))
				return encryptedShare;
		}
		return null;
	}
}