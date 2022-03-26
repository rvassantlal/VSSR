package vssr.dprf;

import java.io.ObjectInput;
import java.io.IOException;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.io.Externalizable;

public class DPRFContribution implements Externalizable {
    private BigInteger ofShareholder;
    private BigInteger forShareholder;
    private BigInteger f;
    private BigInteger z;
    private BigInteger c;
    
    public DPRFContribution() {
    }
    
    public DPRFContribution(BigInteger ofShareholder, BigInteger forShareholder, BigInteger f, BigInteger z, BigInteger c) {
        this.ofShareholder = ofShareholder;
        this.forShareholder = forShareholder;
        this.f = f;
        this.z = z;
        this.c = c;
    }
    
    public BigInteger getForShareholder() {
        return forShareholder;
    }
    
    public BigInteger getOfShareholder() {
        return ofShareholder;
    }
    
    public BigInteger getC() {
        return c;
    }
    
    public BigInteger getF() {
        return f;
    }
    
    public BigInteger getZ() {
        return z;
    }
    
    @Override
    public String toString() {
        return "DPRFContribution{ofShareholder=" + this.ofShareholder + ",\nforShareholder=" + this.forShareholder + ",\nf=" + this.f + ",\nz=" + this.z + ",\nc=" + this.c + '}';
    }
    
    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        serializeBigInteger(ofShareholder, out);
        serializeBigInteger(forShareholder, out);
        serializeBigInteger(f, out);
        serializeBigInteger(z, out);
        serializeBigInteger(c, out);
    }
    
    @Override
    public void readExternal(ObjectInput in) throws IOException {
        this.ofShareholder = deserializeBigInteger(in);
        this.forShareholder = deserializeBigInteger(in);
        this.f = deserializeBigInteger(in);
        this.z = deserializeBigInteger(in);
        this.c = deserializeBigInteger(in);
    }
    
    private static void serializeBigInteger(BigInteger value, ObjectOutput out) throws IOException {
        if (value == null) {
            out.writeInt(-1);
        }
        else {
            byte[] b = value.toByteArray();
            out.writeInt(b.length);
            out.write(b);
        }
    }
    
    private static BigInteger deserializeBigInteger(ObjectInput in) throws IOException {
        int len = in.readInt();
        if (len != -1) {
            byte[] b = new byte[len];
            in.readFully(b);
            return new BigInteger(b);
        }
        return null;
    }
}
