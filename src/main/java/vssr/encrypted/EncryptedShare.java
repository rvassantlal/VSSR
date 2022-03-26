package vssr.encrypted;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Stores a encrypted share of a given shareholder
 *
 * @author Robin
 */
public class EncryptedShare implements Externalizable {
	private BigInteger shareholder;
	private byte[] encryptedShare;

	public EncryptedShare() {}

	public EncryptedShare(BigInteger shareholder, byte[] encryptedShare) {
		this.shareholder = shareholder;
		this.encryptedShare = encryptedShare;
	}

	public BigInteger getShareholder() {
		return shareholder;
	}

	public byte[] getEncryptedShare() {
		return encryptedShare;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		byte[] b = shareholder.toByteArray();
		out.writeInt(b.length);
		out.write(b);

		out.writeInt(encryptedShare.length);
		out.write(encryptedShare);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		byte[] b = new byte[in.readInt()];
		in.readFully(b);
		shareholder = new BigInteger(b);

		encryptedShare = new byte[in.readInt()];
		in.readFully(encryptedShare);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		EncryptedShare that = (EncryptedShare) o;
		return Objects.equals(shareholder, that.shareholder) &&
				Arrays.equals(encryptedShare, that.encryptedShare);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(shareholder);
		result = 31 * result + Arrays.hashCode(encryptedShare);
		return result;
	}
}


