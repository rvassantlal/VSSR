package vssr.interServersCommunication;

import bftsmart.communication.ServerCommunicationSystem;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.core.messages.ForwardedMessage;
import bftsmart.tom.core.messages.TOMMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vssr.MessageType;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class InterServersCommunication {
	private final Logger logger;
	private final TOMMessageGenerator tomMessageGenerator;
	private final ServerCommunicationSystem communicationSystem;
	private final Map<InterServersMessageType, InterServerMessageListener> listeners;

	public InterServersCommunication(ServerCommunicationSystem communicationSystem, ServerViewController viewController) {
		this.logger = LoggerFactory.getLogger("confidential");
		this.tomMessageGenerator = new TOMMessageGenerator(viewController);
		this.communicationSystem = communicationSystem;
		this.listeners = new HashMap<>();
	}

	public SecretKey getSecretKey(int serverId) {
		return this.communicationSystem.getSecretKey(serverId);
	}

	public void sendOrdered(InterServersMessageType type, byte[] metadata, byte[] request, int... targets) {
		TOMMessage msg = tomMessageGenerator.getNextOrdered(metadata, serializeRequest(type, request));
		communicationSystem.send(targets, new ForwardedMessage(msg.getSender(), msg));
	}

	public void sendUnordered(InterServersMessageType type, byte[] request, int... targets) {
		TOMMessage msg = tomMessageGenerator.getNextUnordered(serializeRequest(type, request));
		communicationSystem.send(targets, new ForwardedMessage(msg.getSender(), msg));
	}

	public void registerListener(InterServerMessageListener listener, InterServersMessageType messageType, InterServersMessageType... moreMessageTypes) {
		listeners.put(messageType, listener);
		for (InterServersMessageType type : moreMessageTypes) {
			listeners.put(type, listener);
		}
	}

	public void messageReceived(byte[] message, MessageContext msgCtx) {
		InterServersMessageType type = InterServersMessageType.getType(message[0]);
		byte[] m = Arrays.copyOfRange(message, 1, message.length);
		InterServerMessageListener listener = listeners.get(type);
		if (listener == null) {
			logger.warn("Listener for message type {} not found", type);
		}
		else {
			InterServerMessageHolder holder = new InterServerMessageHolder(type, m, msgCtx);
			listener.messageReceived(holder);
		}
	}

	private byte[] serializeRequest(InterServersMessageType type, byte[] request) {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
			 ObjectOutput out = new ObjectOutputStream(bos)) {
			out.write((byte)MessageType.APPLICATION.ordinal());
			out.writeInt(1 + request.length);
			out.write((byte)type.ordinal());
			out.write(request);
			out.flush();
			bos.flush();
			return bos.toByteArray();
		}catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
}
