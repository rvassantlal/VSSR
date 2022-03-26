package vssr.demo.map;

import bftsmart.tom.MessageContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vssr.ConfidentialData;
import vssr.ConfidentialMessage;
import vssr.server.ConfidentialServerFacade;
import vssr.server.ConfidentialSingleExecutable;
import vssr.statemanagement.ConfidentialSnapshot;

import java.io.*;
import java.util.Map;
import java.util.TreeMap;

public class KVStoreServer implements ConfidentialSingleExecutable {
	private final Logger logger = LoggerFactory.getLogger("demo");
	private Map<String, ConfidentialData> map;

	KVStoreServer(int processId) {
		this.map = new TreeMap<>();
		new ConfidentialServerFacade(processId, this);
	}

	@Override
	public ConfidentialMessage appExecuteOrdered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(plainData);
			 ObjectInput in = new ObjectInputStream(bis)) {
			Operation op = Operation.getOperation(in.read());
			String str;
			ConfidentialData value;
			switch (op) {
				case GET: {
					str = in.readUTF();
					value = this.map.get(str);
					if (value != null) {
						return new ConfidentialMessage(null, value);
					}
					return new ConfidentialMessage();
				}
				case PUT: {
					str = in.readUTF();
					value = map.put(str, shares[0]);
					if (value != null) {
						return new ConfidentialMessage(null, value);
					}
					return new ConfidentialMessage();
				}
				case REMOVE: {
					str = in.readUTF();
					value = map.remove(str);
					if (value != null) {
						return new ConfidentialMessage(null, value);
					}
					return new ConfidentialMessage();
				}
				case GET_ALL: {
					if (map.isEmpty()) {
						return new ConfidentialMessage();
					}
					ConfidentialData[] allValues = new ConfidentialData[map.size()];
					int i = 0;
					for (ConfidentialData share : map.values()) {
						allValues[i++] = share;
					}
					return new ConfidentialMessage(null, allValues);
				}
			}
		} catch (IOException e) {
			this.logger.error("Failed to attend ordered request from {}", msgCtx.getSender(), e);
		}
		return null;
	}

	@Override
	public ConfidentialMessage appExecuteUnordered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(plainData);
			 ObjectInput in = new ObjectInputStream(bis)) {
			Operation op = Operation.getOperation(in.read());
			String str;
			ConfidentialData value;
			switch (op) {
				case GET: {
					str = in.readUTF();
					value = map.get(str);
					if (value != null) {
						return new ConfidentialMessage(null, value);
					}
					return new ConfidentialMessage();
				}
				case GET_ALL: {
					if (map.isEmpty()) {
						return new ConfidentialMessage();
					}
					ConfidentialData[] allValues = (ConfidentialData[]) map.values().toArray();
					return new ConfidentialMessage(null, allValues);
				}
			}
		} catch (IOException e) {
			this.logger.error("Failed to attend unordered request from {}", msgCtx.getSender(), e);
		}
		return null;
	}

	@Override
	public ConfidentialSnapshot getConfidentialSnapshot() {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
			 ObjectOutput out = new ObjectOutputStream(bos)) {
			out.writeInt(map.size());
			ConfidentialData[] shares = new ConfidentialData[map.size()];
			int i = 0;
			for (Map.Entry<String, ConfidentialData> e : map.entrySet()) {
				out.writeUTF(e.getKey());
				shares[i++] = e.getValue();
			}
			out.flush();
			bos.flush();
			return new ConfidentialSnapshot(bos.toByteArray(), shares);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public void installConfidentialSnapshot(ConfidentialSnapshot snapshot) {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(snapshot.getPlainData());
			ObjectInput in = new ObjectInputStream(bis)) {
					int size = in.readInt();
					map = new TreeMap<>();
					ConfidentialData[] shares = snapshot.getShares();
					for (int i = 0; i < size; ++i) {
						map.put(in.readUTF(), shares[i]);
					}
		}catch (IOException e) {
			e.printStackTrace();
		}
	}
}
