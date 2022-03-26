package vssr.benchmark;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.Mode;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.polynomial.Polynomial;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;
import vssr.Configuration;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class RecoveryBenchmark {
	private static SecureRandom rndGenerator;
	private static int threshold;
	private static BigInteger[] shareholders;
	private static int n;
	private static boolean verifyCorrectness;
	private static int nProcessingThreads;

	public static void main(final String[] args) throws SecretSharingException, InterruptedException {
		if (args.length != 7) {
			System.out.println("USAGE: ... confidential.benchmark.RecoveryBenchmark <threshold> <num secrets> <warm up iterations> <test iterations> <num processing threads> <verify correctness> <commitment scheme -> linear|constant>");
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

		shareholders = new BigInteger[n];
		for (int i = 0; i < n; ++i) {
			final BigInteger shareholder = BigInteger.valueOf(i + 1);
			shareholders[i] = shareholder;
		}
		Configuration configuration = Configuration.getInstance();
		Properties properties = new Properties();
		properties.put("threshold", String.valueOf(threshold));
		properties.put("dataEncAlgorithm", configuration.getDataEncryptionAlgorithm());
		properties.put("shareEncAlgorithm", configuration.getShareEncryptionAlgorithm());
		properties.put("p", configuration.getPrimeField());
		properties.put("q", configuration.getSubPrimeField());
		properties.put("g", configuration.getGenerator());
		if (commitmentSchemeName.equals("linear")) {
			properties.put("commitmentScheme", "1");
		}
		else {
			if (!commitmentSchemeName.equals("constant")) {
				throw new IllegalStateException("Commitment scheme is unknown");
			}
			properties.put("commitmentScheme", "2");
		}
		rndGenerator = new SecureRandom("ola".getBytes());
		VSSFacade vssFacade = new VSSFacade(properties, shareholders);
		System.out.println("Warming up (" + warmUpIterations + " iterations)");
		if (warmUpIterations > 0) {
			runTests(warmUpIterations, false, nSecrets, vssFacade);
		}
		System.out.println("Running test (" + testIterations + " iterations)");
		if (testIterations > 0) {
			runTests(testIterations, true, nSecrets, vssFacade);
		}
	}

	private static void runTests(int nTests, boolean printResults, int nSecrets, VSSFacade vssFacade) throws SecretSharingException, InterruptedException {
		int recoveryShareholderIndex = 0;
		BigInteger field = vssFacade.getField();
		CommitmentScheme commitmentScheme = vssFacade.getCommitmentScheme();
		Polynomial r = createRecoveryPolynomialFor(recoveryShareholderIndex, vssFacade);
		Commitment rCommitment = commitmentScheme.generateCommitments(r);
		BigInteger[] rPoints = generateShares(RecoveryBenchmark.shareholders, r);

		byte[] secret = new byte[1024];
		rndGenerator.nextBytes(secret);
		OpenPublishedShares privateShares = vssFacade.share(secret, Mode.LARGE_SECRET, threshold);
		Set<BigInteger> corruptedServers = new HashSet<>(RecoveryBenchmark.threshold);

		long[] recoveryShareGenerationTimes = new long[nTests];
		long[] sharesRecoveryTimes = new long[nTests];
		long[] commitmentsRecoveryTimes = new long[nTests];
		long[] allTimes = new long[nTests];
		for (int nT = 0; nT < nTests; ++nT) {
			corruptedServers.clear();
			long recoveryShareGenerationTime = 0L;
			long sharesRecoveryTime = 0L;
			long commitmentsRecoveryTime = 0L;
			long allTimeStart = System.nanoTime();
			VerifiableShare[][] allVerifiableShares = new VerifiableShare[nSecrets][];
			for (int nS = 0; nS < nSecrets; ++nS) {
				VerifiableShare[] verifiableShares = new VerifiableShare[RecoveryBenchmark.n];
				for (int i = 0; i < RecoveryBenchmark.n; ++i) {
					if (i != recoveryShareholderIndex) {
						verifiableShares[i] = new VerifiableShare(privateShares.getShares()[i], privateShares.getCommitments(), privateShares.getSharedData());
					}
				}
				allVerifiableShares[nS] = verifiableShares;
			}
			byte[] sharedData = allVerifiableShares[0][(recoveryShareholderIndex + 1) % RecoveryBenchmark.n].getSharedData();
			Share[][] allRecoveryShares = new Share[nSecrets][];
			for (int nS = 0; nS < nSecrets; ++nS) {
				VerifiableShare[] verifiableShares2 = allVerifiableShares[nS];
				Share[] recoveryShares = new Share[RecoveryBenchmark.n - 1];
				int j = 0;
				int k = 0;
				while (j < RecoveryBenchmark.n) {
					if (j != recoveryShareholderIndex) {
						VerifiableShare vs = verifiableShares2[j];
						if (j == (recoveryShareholderIndex + 1) % RecoveryBenchmark.n) {
							long start = System.nanoTime();
							recoveryShares[k++] = new Share(vs.getShare().getShareholder(), vs.getShare().getShare().add(rPoints[j]).mod(field));
							long end = System.nanoTime();
							recoveryShareGenerationTime += end - start;
						}
						else {
							recoveryShares[k++] = new Share(vs.getShare().getShareholder(), vs.getShare().getShare().add(rPoints[j]).mod(field));
						}
					}
					++j;
				}
				allRecoveryShares[nS] = recoveryShares;
			}
			ExecutorService executor = Executors.newFixedThreadPool(nProcessingThreads);
			CountDownLatch commitmentRecoveryCounter = new CountDownLatch(nSecrets);
			Commitment[] allRecoveredCommitment = new Commitment[nSecrets];
			Map<BigInteger, Commitment>[] allRecoveryCommitments = new HashMap[nSecrets];
			long start = System.nanoTime();
			for (int nS = 0; nS < nSecrets; ++nS) {
				int finalNS = nS;
				VerifiableShare[] verifiableShares = allVerifiableShares[nS];
				executor.execute(() -> {
					int minNumberOfCommitments = (corruptedServers.size() >= threshold) ? threshold : (threshold + 1);
					Map<BigInteger, Commitment> validCommitments = new HashMap<>(minNumberOfCommitments);
					for (int l = 0; l < n; ++l) {
						if (l != recoveryShareholderIndex) {
							validCommitments.put(shareholders[l], verifiableShares[l].getCommitments());
							if (validCommitments.size() == minNumberOfCommitments) {
								break;
							}
						}
					}
					Commitment recoveredCommitment;
					try {
						recoveredCommitment = commitmentScheme.recoverCommitment(shareholders[recoveryShareholderIndex], validCommitments);
					} catch (SecretSharingException e) {
						System.err.println("Invalid Commitments");
						validCommitments.clear();
						recoveredCommitment = null;
						System.exit(-1);
					}
					allRecoveryCommitments[finalNS] = validCommitments;
					allRecoveredCommitment[finalNS] = recoveredCommitment;
					commitmentRecoveryCounter.countDown();
				});
			}
			executor.shutdown();
			commitmentRecoveryCounter.await();
			long end = System.nanoTime();
			commitmentsRecoveryTime += end - start;
			executor = Executors.newFixedThreadPool(RecoveryBenchmark.nProcessingThreads);
			CountDownLatch shareRecoveryCounter = new CountDownLatch(nSecrets);
			VerifiableShare[] allRecoveredShares = new VerifiableShare[nSecrets];
			start = System.nanoTime();
			for (int nS = 0; nS < nSecrets; ++nS) {
				int finalNS2 = nS;
				Map<BigInteger, Commitment> recoveryCommitments = allRecoveryCommitments[nS];
				Commitment recoveredCommitment = allRecoveredCommitment[nS];
				Share[] recoveryShares = allRecoveryShares[nS];

				executor.execute(() -> {
					try {
						Share[] recoveringShares = new Share[threshold + (corruptedServers.size() < RecoveryBenchmark.threshold ? 2 : 1)];
						Map<BigInteger, Share> allRecoveringShares = new HashMap<>();

						for (int i = 0, j = 0; i < recoveringShares.length; i++) {
							Share share = recoveryShares[i];
							if (share == null)
								continue;
							if (j < recoveringShares.length && !corruptedServers.contains(share.getShareholder()))
								recoveringShares[j++] = share;
							allRecoveringShares.put(share.getShareholder(), share);
						}

						Polynomial polynomial = new Polynomial(field, recoveringShares);
						BigInteger shareNumber;
						if (polynomial.getDegree() != RecoveryBenchmark.threshold) {
							recoveringShares = new Share[RecoveryBenchmark.threshold + 1];
							Commitment combinedCommitment = commitmentScheme.combineCommitments(recoveryCommitments);
							Commitment verificationCommitment = commitmentScheme.sumCommitments(rCommitment, combinedCommitment);
							commitmentScheme.startVerification(verificationCommitment);
							int j = 0;
							for (Map.Entry<BigInteger, Share> entry : allRecoveringShares.entrySet()) {
								if (commitmentScheme.checkValidity(entry.getValue(), verificationCommitment)) {
									recoveringShares[j++] = entry.getValue();
								} else {
									corruptedServers.add(entry.getValue().getShareholder());
								}
							}
							commitmentScheme.endVerification();
							shareNumber = vssFacade.getInterpolationStrategy()
									.interpolateAt(shareholders[recoveryShareholderIndex], recoveringShares);
						} else {
							shareNumber = polynomial.evaluateAt(shareholders[recoveryShareholderIndex]);
						}
						Share recoveredShare = new Share(shareholders[recoveryShareholderIndex], shareNumber);
						allRecoveredShares[finalNS2] = new VerifiableShare(recoveredShare, recoveredCommitment, sharedData);
						shareRecoveryCounter.countDown();
					} catch (SecretSharingException e) {
						e.printStackTrace();
					}
				});
			}
			executor.shutdown();
			shareRecoveryCounter.await();
			end = System.nanoTime();
			sharesRecoveryTime += end - start;
			if (verifyCorrectness) {
				for (int nS = 0; nS < nSecrets; ++nS) {
					VerifiableShare[] verifiableShares = allVerifiableShares[nS];
					verifiableShares[recoveryShareholderIndex] = allRecoveredShares[nS];
					Share[] shares = new Share[n];
					Map<BigInteger, Commitment> commitments = new HashMap<>(n);
					for (int i = 0; i < n; ++i) {
						VerifiableShare vs = verifiableShares[i];
						shares[i] = vs.getShare();
						commitments.put(vs.getShare().getShareholder(), vs.getCommitments());
					}
					Commitment commitment = commitmentScheme.combineCommitments(commitments);
					OpenPublishedShares openShares = new OpenPublishedShares(shares, commitment, sharedData);
					byte[] recoveredSecret = vssFacade.combine(openShares, Mode.LARGE_SECRET, threshold);
					if (!Arrays.equals(secret, recoveredSecret)) {
						throw new IllegalStateException("Secret is different");
					}
				}
			}
			long allTimeEnd = System.nanoTime();
			recoveryShareGenerationTimes[nT] = recoveryShareGenerationTime;
			sharesRecoveryTimes[nT] = sharesRecoveryTime;
			commitmentsRecoveryTimes[nT] = commitmentsRecoveryTime;
			allTimes[nT] = allTimeEnd - allTimeStart;
		}
		if (printResults) {
			double recoveryShareGeneration = computeAverage(recoveryShareGenerationTimes) / 1000000.0;
			double sharesRecovery = computeAverage(sharesRecoveryTimes) / 1000000.0;
			double commitmentsRecovery = computeAverage(commitmentsRecoveryTimes) / 1000000.0;
			double allTimeAvg = computeAverage(allTimes) / 1000000.0;
			System.out.println("Recovery share generation: " + recoveryShareGeneration + " ms");
			System.out.println("Share recovery: " + sharesRecovery + " ms");
			System.out.println("Commitment recovery: " + commitmentsRecovery + " ms");
			System.out.println("Recovery total: " + (recoveryShareGeneration + sharesRecovery + commitmentsRecovery) + " ms");
			System.out.println("All: " + allTimeAvg + " ms");
		}
	}

	private static double computeAverage(long[] values) {
		return Arrays.stream(values).sum() / (double)values.length;
	}

	private static BigInteger[] generateShares(BigInteger[] shareholders, Polynomial polynomial) {
		BigInteger[] result = new BigInteger[shareholders.length];
		for (int i = 0; i < shareholders.length; ++i) {
			result[i] = polynomial.evaluateAt(shareholders[i]);
		}
		return result;
	}

	private static Polynomial createRecoveryPolynomialFor(int recoveryShareholderIndex, VSSFacade vssFacade) {
		Polynomial tempPolynomial = new Polynomial(vssFacade.getField(), threshold, BigInteger.ZERO, rndGenerator);
		BigInteger independentTerm = tempPolynomial.evaluateAt(shareholders[recoveryShareholderIndex]).negate();
		BigInteger[] tempCoefficients = tempPolynomial.getCoefficients();
		BigInteger[] coefficients = Arrays.copyOfRange(tempCoefficients,
				tempCoefficients.length - tempPolynomial.getDegree() - 1, tempCoefficients.length - 1);
		return new Polynomial(vssFacade.getField(), independentTerm, coefficients);
	}
}
