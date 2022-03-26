package vssr.dprf;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.polynomial.Polynomial;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DPRFScheme {
    private static final byte[] SEED = "vssr".getBytes();
    private final Logger logger;
    private final BigInteger field;
    private final BigInteger generator;
    private MessageDigest digest;
    private final Lock hashLock;
    private final SecureRandom rndGenerator;
    private final BigInteger alpha;
    private int threshold;
    
    public DPRFScheme(BigInteger field, BigInteger generator) {
        this.logger = LoggerFactory.getLogger("vssr");
        this.field = field;
        this.generator = generator;
        this.rndGenerator = new SecureRandom(DPRFScheme.SEED);
        try {
            this.digest = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e) {
            this.logger.error("Failed to instantiate Message Digest.", e);
            System.exit(-1);
        }
        this.hashLock = new ReentrantLock();
        this.alpha = new BigInteger("8212358705384120491879690644965329697418472285881853302754892007160277640199");
    }
    
    public DPRFParameters init(int threshold, BigInteger[] shareholders) {
        this.threshold = threshold;
        Polynomial polynomial = new Polynomial(field, alpha, new BigInteger[] { this.alpha });
        Map<BigInteger, DPRFPrivateParameters> privateParameters = new HashMap<>(shareholders.length);
        Map<BigInteger, BigInteger> hAlphaShares = new HashMap<>(shareholders.length);
        for (BigInteger shareholder : shareholders) {
            BigInteger share = polynomial.evaluateAt(shareholder);
            privateParameters.put(shareholder, new DPRFPrivateParameters(share));
            hAlphaShares.put(shareholder, generator.modPow(share, field));
        }
        BigInteger hAlpha = generator.modPow(alpha, field);
        DPRFPublicParameters publicParameters = new DPRFPublicParameters(generator, hAlpha, hAlphaShares);
        return new DPRFParameters(publicParameters, privateParameters);
    }
    
    public DPRFContribution contribute(BigInteger ofShareholder, DPRFPrivateParameters privateParameters, BigInteger r, BigInteger forShareholder) {
        BigInteger alphaShare = privateParameters.getAlphaShare();
        byte[] xH = hash(forShareholder.toByteArray());
        BigInteger xHNumber = new BigInteger(xH);
        BigInteger f = xHNumber.modPow(alphaShare, field);
        BigInteger ha = generator.modPow(alphaShare, field);
        BigInteger xhr = xHNumber.modPow(r, field);
        BigInteger hr = generator.modPow(r, field);
        byte[] cBytes = hash(xH, generator.toByteArray(), f.toByteArray(), ha.toByteArray(), xhr.toByteArray(), hr.toByteArray());
        BigInteger c = new BigInteger(cBytes);
        BigInteger z = alphaShare.multiply(c).add(r);
        return new DPRFContribution(ofShareholder, forShareholder, f, z, c);
    }
    
    public boolean verify(DPRFPublicParameters publicParameters, DPRFContribution d) {
        BigInteger hAlpha = publicParameters.getHSharesOf(d.getOfShareholder());
        byte[] xH = hash(d.getForShareholder().toByteArray());
        BigInteger f = d.getF();
        BigInteger xhz = new BigInteger(xH).modPow(d.getZ(), field).multiply(f.modPow(d.getC(), field).modInverse(field)).mod(field);
        BigInteger hz = generator.modPow(d.getZ(), field).multiply(hAlpha.modPow(d.getC(), field).modInverse(field)).mod(field);
        byte[] hash = hash(xH, generator.toByteArray(), f.toByteArray(), hAlpha.toByteArray(), xhz.toByteArray(), hz.toByteArray());
        return d.getC().equals(new BigInteger(hash));
    }
    
    public BigInteger evaluate(DPRFPublicParameters publicParameters, BigInteger x, DPRFContribution... d) {
        LinkedList<DPRFContribution> contributionsList = new LinkedList<>();
        for (DPRFContribution contribute : d) {
            if (!contribute.getOfShareholder().equals(x)) {
                if (!verify(publicParameters, contribute)) {
                    logger.error("DPRF contribution is invalid");
                    return null;
                }
                contributionsList.add(contribute);
                if (contributionsList.size() > threshold) {
                    break;
                }
            }
        }
        DPRFContribution[] contributions = contributionsList.toArray(new DPRFContribution[0]);
        BigInteger generator = new BigInteger(hash(x.toByteArray()));
        BigInteger result = BigInteger.ZERO;
        for (int di = 0; di < contributions.length; ++di) {
            DPRFContribution i = contributions[di];
            BigInteger l = i.getF();
            BigInteger gx = generator.modPow(x, field);
            BigInteger gxi = generator.modPow(i.getOfShareholder(), field);
            for (int dj = 0; dj < contributions.length; ++dj) {
                DPRFContribution j = contributions[dj];
                if (di != dj) {
                    BigInteger xj = generator.modPow(j.getOfShareholder(), field);
                    BigInteger numerator = gx.subtract(xj);
                    BigInteger denominator = gxi.subtract(xj);
                    BigInteger li = numerator.multiply(denominator.modInverse(field));
                    l = l.multiply(li).mod(field);
                }
            }
            result = result.add(l).mod(field);
        }
        return new BigInteger(hash(result.toByteArray()));
    }
    
    private byte[] hash(byte[]... data) {
        hashLock.lock();
        for (byte[] datum : data) {
            digest.update(datum);
        }
        byte[] result = digest.digest();
        hashLock.unlock();
        return result;
    }
    
    public BigInteger getRandomNumber() {
        int numBits = field.bitLength() - 1;
        BigInteger rndBig = new BigInteger(numBits, rndGenerator);
        if (rndBig.compareTo(BigInteger.ZERO) == 0) {
            rndBig = rndBig.add(BigInteger.ONE);
        }
        return rndBig;
    }
}
