package vssr.statemanagement.privatestate.sender;

import bftsmart.communication.SystemMessage;
import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.secretsharing.VerifiableShare;
import vssr.ConfidentialData;
import vssr.VSSRShare;
import vssr.server.Request;
import vssr.server.ServerConfidentialityScheme;
import vssr.statemanagement.ConfidentialSnapshot;
import vssr.statemanagement.utils.HashThread;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

public abstract class BlindedStateSender extends Thread {
	protected final Logger logger;
	private final ServerViewController svController;
	private final int pid;
	private DefaultApplicationState applicationState;
	private final int blindedStateReceiverPort;
	protected final ServerConfidentialityScheme confidentialityScheme;
	private final boolean iAmStateSender;
	protected final int[] blindedStateReceivers;

	public BlindedStateSender(ServerViewController svController, DefaultApplicationState applicationState,
							  int blindedStateReceiverPort, ServerConfidentialityScheme confidentialityScheme,
							  boolean iAmStateSender, int... blindedStateReceivers) {
		super("Blinded State Sender Thread");
		this.logger = LoggerFactory.getLogger("state_transfer");
		this.svController = svController;
		this.pid = svController.getStaticConf().getProcessId();
		this.applicationState = applicationState;
		this.blindedStateReceiverPort = blindedStateReceiverPort;
		this.confidentialityScheme = confidentialityScheme;
		this.iAmStateSender = iAmStateSender;
		this.blindedStateReceivers = blindedStateReceivers;
	}

	@Override
	public void run() {
		logger.debug("Generating Blinded State");
		try {
			long totalElapsed = 0L;
			long t1 = System.nanoTime();
			SeparatedState separatedState = separatePrivateState(applicationState);
			long t2 = System.nanoTime();
			totalElapsed += t2 - t1;
			applicationState = null;
			if (separatedState == null) {
				logger.error("Separated state is null. Exiting blinded state sender thread.");
				return;
			}
			BlindedDataSender[] stateSenders = new BlindedDataSender[blindedStateReceivers.length];
			for (int i = 0; i < blindedStateReceivers.length; ++i) {
				int blindedStateReceiver = blindedStateReceivers[i];
				String receiverIp = this.svController.getCurrentView().getAddress(blindedStateReceiver).getAddress().getHostAddress();
				int port = this.blindedStateReceiverPort + blindedStateReceiver;
				BlindedDataSender stateSender = new BlindedDataSender(pid, receiverIp, port, iAmStateSender);
				stateSender.start();
				stateSenders[i] = stateSender;
			}
			HashThread commonStateHashThread = null;
			if (iAmStateSender) {
				for (BlindedDataSender stateSender : stateSenders) {
					stateSender.setCommonState(separatedState.getCommonState(), null);
				}
			}
			else {
				commonStateHashThread = new HashThread();
				commonStateHashThread.setData(separatedState.getCommonState());
				commonStateHashThread.start();
				commonStateHashThread.update(0, separatedState.getCommonState().length);
				commonStateHashThread.update(-1, -1);
			}
			if (commonStateHashThread != null) {
				byte[] commonStateHash = commonStateHashThread.getHash();
				for (BlindedDataSender stateSender : stateSenders) {
					stateSender.setCommonState(null, commonStateHash);
				}
			}
			t1 = System.nanoTime();
			BlindedShares blindedShares = computeBlindedShares(separatedState.getShares());
			t2 = System.nanoTime();
			totalElapsed += t2 - t1;
			double total = totalElapsed / 1000000.0;
			if (blindedShares == null) {
				logger.error("Blinded shares are null. Exiting blinded state sender thread.");
				return;
			}
			logger.info("Took {} ms to compute blinded state", total);
			for (BlindedDataSender stateSender : stateSenders) {
				stateSender.setBlindedShares(blindedShares);
			}
		} catch (NoSuchAlgorithmException e) {
			logger.error("Failed to create hash thread.", e);
		}
		logger.debug("Existing blinded state sender thread");
	}

	protected abstract BlindedShares computeBlindedShares(LinkedList<VSSRShare> p0);

	private SeparatedState separatePrivateState(DefaultApplicationState state) {
		try (ByteArrayOutputStream bosCommonState = new ByteArrayOutputStream();
			 ObjectOutput outCommonState = new ObjectOutputStream(bosCommonState)) {
			LinkedList<VSSRShare> sharesToSend = new LinkedList<>();
			CommandsInfo[] log = state.getMessageBatches();
			outCommonState.writeInt(state.getLastCheckpointCID());
			outCommonState.writeInt(state.getLastCID());
			outCommonState.writeInt((log == null) ? -1 : log.length);
			if (log != null) {
				separateLog(log, outCommonState, sharesToSend);
			}
			ConfidentialSnapshot snapshot = null;
			if (state.hasState()) {
				snapshot = ConfidentialSnapshot.deserialize(state.getSerializedState());
			}
			if (snapshot != null) {
				outCommonState.writeBoolean(true);
				separateSnapshot(snapshot, outCommonState, sharesToSend);
			}
			else {
				outCommonState.writeBoolean(false);
			}
			outCommonState.flush();
			bosCommonState.flush();
			byte[] commonStateBytes = bosCommonState.toByteArray();
			return new SeparatedState(commonStateBytes, sharesToSend);
		} catch (IOException e) {
			logger.error("Failed to create separate private state", e);
			return null;
		}
	}

	private void separateSnapshot(ConfidentialSnapshot snapshot, ObjectOutput outCommonState,
								  LinkedList<VSSRShare> sharesToSend) throws IOException {
		outCommonState.writeInt((snapshot.getPlainData() == null) ? -1 : snapshot.getPlainData().length);
		if (snapshot.getPlainData() != null) {
			outCommonState.write(snapshot.getPlainData());
		}
		outCommonState.writeInt((snapshot.getShares() == null) ? -1 : snapshot.getShares().length);
		if (snapshot.getShares() != null) {
			this.separateShares(snapshot.getShares(), outCommonState, sharesToSend);
		}
	}

	private void separateLog(CommandsInfo[] log, ObjectOutput outCommonState, LinkedList<VSSRShare> sharesToSend) throws IOException {
		for (CommandsInfo commandsInfo : log) {
			byte[][] commands = commandsInfo.commands;
			MessageContext[] msgCtx = commandsInfo.msgCtx;
			serializeMessageContext(outCommonState, msgCtx);
			outCommonState.writeInt(commands.length);
			for (byte[] command : commands) {
				Request request = Request.deserialize(command);
				if (request == null || request.getShares() == null) {
					outCommonState.writeInt(-1);
					outCommonState.writeInt(command.length);
					outCommonState.write(command);
				}
				else {
					outCommonState.writeInt(request.getShares().length);
					separateShares(request.getShares(), outCommonState, sharesToSend);
					request.setShares(null);
					byte[] b = request.serialize();
					if (b == null) {
						logger.debug("Failed to serialize blinded request");
						return;
					}
					outCommonState.writeInt(b.length);
					outCommonState.write(b);
				}
			}
		}
	}

	private void separateShares(ConfidentialData[] shares, ObjectOutput outCommonState, LinkedList<VSSRShare> sharesToSend) throws IOException {
		for (ConfidentialData share : shares) {
			VerifiableShare s = share.getShare().getShareAtIndex(0);
			byte[] b = s.getSharedData();
			outCommonState.writeInt((b == null) ? -1 : b.length);
			if (b != null) {
				outCommonState.write(b);
			}
			sharesToSend.add(share.getShare());
		}
	}

	private void serializeMessageContext(ObjectOutput out, MessageContext[] msgCtx) throws IOException {
		out.writeInt((msgCtx == null) ? -1 : msgCtx.length);
		if (msgCtx == null) {
			return;
		}
		for (MessageContext ctx : msgCtx) {
			out.writeInt(ctx.getSender());
			out.writeInt(ctx.getViewID());
			out.writeInt(ctx.getType().ordinal());
			out.writeInt(ctx.getSession());
			out.writeInt(ctx.getSequence());
			out.writeInt(ctx.getOperationId());
			out.writeInt(ctx.getReplyServer());
			out.writeInt((ctx.getSignature() == null) ? -1 : ctx.getSignature().length);
			if (ctx.getSignature() != null) {
				out.write(ctx.getSignature());
			}
			out.writeLong(ctx.getTimestamp());
			out.writeInt(ctx.getRegency());
			out.writeInt(ctx.getLeader());
			out.writeInt(ctx.getConsensusId());
			out.writeInt(ctx.getNumOfNonces());
			out.writeLong(ctx.getSeed());
			out.writeInt((ctx.getMetadata() == null) ? -1 : ctx.getMetadata().length);
			if (ctx.getMetadata() != null) {
				out.write(ctx.getMetadata());
			}
			out.writeInt((ctx.getProof() == null) ? -1 : ctx.getProof().size());
			if (ctx.getProof() != null) {
				final List<ConsensusMessage> orderedProf = new ArrayList<>(ctx.getProof());
				orderedProf.sort(Comparator.comparingInt(SystemMessage::getSender));
				for (final ConsensusMessage proof : orderedProf) {
					out.writeInt(proof.getNumber());
					out.writeInt(proof.getEpoch());
					out.writeInt(proof.getType());
					out.writeInt((proof.getValue() == null) ? -1 : proof.getValue().length);
					if (proof.getValue() != null) {
						out.write(proof.getValue());
					}
				}
			}
			out.writeBoolean(ctx.isLastInBatch());
			out.writeBoolean(ctx.isNoOp());
			out.writeInt((ctx.getNonces() == null) ? -1 : ctx.getNonces().length);
			if (ctx.getNonces() != null) {
				out.write(ctx.getNonces());
			}
		}
	}
}
