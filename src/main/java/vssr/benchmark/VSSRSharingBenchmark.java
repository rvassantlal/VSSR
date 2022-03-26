package vssr.benchmark;

import bftsmart.reconfiguration.views.View;
import vss.commitment.Commitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vssr.RecoveryContribution;
import vssr.VSSRPublishedShares;
import vssr.VSSRShare;
import vssr.client.ClientConfidentialityScheme;
import vssr.server.ServerConfidentialityScheme;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class VSSRSharingBenchmark {
    private static SecureRandom rndGenerator;
    private static int threshold;
    private static int n;
    private static boolean verifyCorrectness;
    private static int nProcessingThreads;
    
    public static void main(String[] args) throws SecretSharingException {
        if (args.length != 7) {
            System.out.println("USAGE: ... confidential.benchmark.VSSRSharingBenchmark <threshold> <num secrets> <warm up iterations> <test iterations> <num processing threads> <verify correctness> <commitment scheme -> linear|constant>");
            System.exit(-1);
        }
        threshold = Integer.parseInt(args[0]);
        int nSecrets = Integer.parseInt(args[1]);
        int warmUpIterations = Integer.parseInt(args[2]);
        int testIterations = Integer.parseInt(args[3]);
        nProcessingThreads = Integer.parseInt(args[4]);
        verifyCorrectness = Boolean.parseBoolean(args[5]);
        String commitmentSchemeName = args[6];
        n = 3 * threshold + 1;
        System.out.println("t = " + threshold);
        System.out.println("n = " + n);
        System.out.println("number of secrets = " + nSecrets);
        System.out.println("commitment scheme = " + commitmentSchemeName);
        System.out.println();
        int[] servers = new int[n];
        InetSocketAddress[] inetSocketAddresses = new InetSocketAddress[n];
        for (int i = 0; i < n; ++i) {
            inetSocketAddresses[servers[i] = i] = new InetSocketAddress(2);
        }
        VSSRSharingBenchmark.rndGenerator = new SecureRandom("ola".getBytes());
        View view = new View(100, servers, threshold, inetSocketAddresses);
        ClientConfidentialityScheme clientConfidentialityScheme = new ClientConfidentialityScheme(view);
        ServerConfidentialityScheme[] serverConfidentialitySchemes = new ServerConfidentialityScheme[n];
        for (int j = 0; j < n; ++j) {
            serverConfidentialitySchemes[j] = new ServerConfidentialityScheme(j, view);
        }
        System.out.println("Warming up (" + warmUpIterations + " iterations)");
        if (warmUpIterations > 0) {
            runTests(warmUpIterations, false, nSecrets, clientConfidentialityScheme, serverConfidentialitySchemes);
        }
        System.out.println("Running test (" + testIterations + " iterations)");
        if (testIterations > 0) {
            runTests(testIterations, true, nSecrets, clientConfidentialityScheme, serverConfidentialitySchemes);
        }
    }
    
    private static void runTests(int nTests, boolean printResults, int nSecrets,
                                 ClientConfidentialityScheme clientConfidentialityScheme,
                                 ServerConfidentialityScheme[] serverConfidentialitySchemes) throws SecretSharingException {
        int recoveryShareholderIndex = 0;
        byte[] secret = new byte[1024];
        rndGenerator.nextBytes(secret);
        long[] shareTimes = new long[nTests];
        long[] shareExtractTimes = new long[nTests];
        long[] recoveryShareGenerationTimes = new long[nTests];
        long[] shareRecoveryTimes = new long[nTests];
        long[] combineTimes = new long[nTests];
        long[] totalTimes = new long[nTests];
        for (int nT = 0; nT < nTests; ++nT) {
            long shareTime = 0L;
            long shareExtractTime = 0L;
            long recoveryShareGenerationTime = 0L;
            long shareRecoveryTime = 0L;
            long combineTime = 0L;
            final long totalStart = System.nanoTime();
            for (int nS = 0; nS < nSecrets; ++nS) {
                long start = System.nanoTime();
                VSSRPublishedShares privateShares = clientConfidentialityScheme.share(secret);
                long end = System.nanoTime();
                shareTime += end - start;
                start = System.nanoTime();
                VSSRShare[] shares = new VSSRShare[n];
                for (int i = 0; i < n; ++i) {
                    if (i != recoveryShareholderIndex) {
                        shares[i] = serverConfidentialitySchemes[i].extractShare(privateShares);
                    }
                }
                end = System.nanoTime();
                shareExtractTime += end - start;
                for (int i = 0; i < n; ++i) {
                    if (i != recoveryShareholderIndex) {
                        if (!serverConfidentialitySchemes[i].verify(shares[i])) {
                            throw new IllegalStateException("Extracted share is invalid");
                        }
                    }
                }
                RecoveryContribution[] recoveryContributions = new RecoveryContribution[shares.length - 1];
                int k = 0;
                for (int j = 0; j < shares.length; ++j) {
                    if (j != recoveryShareholderIndex) {
                        if (j == (recoveryShareholderIndex + 1) % n) {
                            start = System.nanoTime();
                            recoveryContributions[k++] = serverConfidentialitySchemes[j].recoveryContribution(shares[j], serverConfidentialitySchemes[j].getShareholder(recoveryShareholderIndex));
                            end = System.nanoTime();
                            recoveryShareGenerationTime += end - start;
                        }
                        else {
                            recoveryContributions[k++] = serverConfidentialitySchemes[j].recoveryContribution(shares[j], serverConfidentialitySchemes[j].getShareholder(recoveryShareholderIndex));
                        }
                    }
                }
                start = System.nanoTime();
                shares[recoveryShareholderIndex] = serverConfidentialitySchemes[recoveryShareholderIndex].recoverShare(recoveryContributions);
                if (shares[recoveryShareholderIndex] == null) {
                    throw new IllegalStateException("Recovered share is null");
                }
                end = System.nanoTime();
                shareRecoveryTime += end - start;
                if (verifyCorrectness) {
                    start = System.nanoTime();
                    final Share[] s = new Share[threshold + 1];
                    s[0] = shares[recoveryShareholderIndex].getShareAtIndex(0).getShare();
                    final Map<BigInteger, Commitment> commitments = new HashMap<>(threshold + 1);
                    commitments.put(s[0].getShareholder(), shares[recoveryShareholderIndex].getShareAtIndex(0).getCommitments());
                    k = 1;
                    for (int l = 0; l < shares.length; ++l) {
                        if (l != recoveryShareholderIndex) {
                            s[k] = shares[l].getShareAtIndex(0).getShare();
                            commitments.put(s[k].getShareholder(), shares[recoveryShareholderIndex].getShareAtIndex(0).getCommitments());
                            if (++k == s.length) {
                                break;
                            }
                        }
                    }
                    Commitment commitment = clientConfidentialityScheme.getCommitmentScheme().combineCommitments(commitments);
                    OpenPublishedShares openShares = new OpenPublishedShares(s, commitment, privateShares.getSharedData());
                    byte[] recoveredSecret = clientConfidentialityScheme.combine(openShares);
                    if (recoveredSecret == null) {
                        throw new IllegalStateException("Recovered secret is null");
                    }
                    if (!Arrays.equals(secret, recoveredSecret)) {
                        throw new IllegalStateException("Secret is different");
                    }
                    end = System.nanoTime();
                    combineTime += end - start;
                }
            }
            long totalEnd = System.nanoTime();
            shareTimes[nT] = shareTime;
            shareExtractTimes[nT] = shareExtractTime;
            recoveryShareGenerationTimes[nT] = recoveryShareGenerationTime;
            shareRecoveryTimes[nT] = shareRecoveryTime;
            combineTimes[nT] = combineTime;
            totalTimes[nT] = totalEnd - totalStart;
        }
        if (printResults) {
            double shareAvg = computeAverage(shareTimes);
            double shareExtractAvg = computeAverage(shareExtractTimes);
            double recoveryShareGenerationAvg = computeAverage(recoveryShareGenerationTimes);
            double shareRecoveryAvg = computeAverage(shareRecoveryTimes);
            double combineAvg = computeAverage(combineTimes);
            double totalAvg = computeAverage(totalTimes);
            System.out.println("Share: " + shareAvg + " ms");
            System.out.println("Share extract: " + shareExtractAvg + " ms");
            System.out.println("Recovery share generation: " + recoveryShareGenerationAvg + " ms");
            System.out.println("Share recovery: " + shareRecoveryAvg + " ms");
            System.out.println("Combine: " + combineAvg + " ms");
            System.out.println("All total " + totalAvg + " ms");
        }
    }
    
    private static double computeAverage(long[] values) {
        return Arrays.stream(values).sum() / (double)values.length / 1000000.0;
    }
}
