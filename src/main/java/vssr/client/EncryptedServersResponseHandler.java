package vssr.client;

import bftsmart.tom.core.messages.TOMMessage;
import vss.commitment.Commitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vssr.ExtractedResponse;
import vssr.encrypted.EncryptedConfidentialData;
import vssr.encrypted.EncryptedConfidentialMessage;
import vssr.encrypted.EncryptedVerifiableShare;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

public class EncryptedServersResponseHandler extends ServersResponseHandler {
    private final Map<byte[], EncryptedConfidentialMessage> responses;
    private final Map<EncryptedConfidentialMessage, Integer> responseHashes;
    private final int clientId;

    public EncryptedServersResponseHandler(int clientId) {
        this.clientId = clientId;
        this.responses = new HashMap<>();
        this.responseHashes = new HashMap<>();
    }

    public TOMMessage extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
        Map<Integer, LinkedList<EncryptedConfidentialMessage>> msgs = new HashMap<>();
        for (TOMMessage msg : replies) {
            if (msg != null) {
                EncryptedConfidentialMessage response = responses.get(msg.getContent());
                if (response == null) {
                    logger.warn("Something went wrong while getting deserialized response from {}", msg.getSender());
                }
                else {
                    int responseHash = this.responseHashes.get(response);
                    LinkedList<EncryptedConfidentialMessage> msgList = msgs.computeIfAbsent(responseHash,
                            k -> new LinkedList<>());
                    msgList.add(response);
                }
            }
        }
        for (LinkedList<EncryptedConfidentialMessage> msgList : msgs.values()) {
            if (msgList.size() == sameContent) {
                EncryptedConfidentialMessage firstMsg = msgList.getFirst();
                byte[] plainData = firstMsg.getPlainData();
                byte[][] confidentialData = null;
                if (firstMsg.getShares() != null) {
                    int numSecrets = firstMsg.getShares().length;
                    ArrayList<LinkedList<EncryptedVerifiableShare>> verifiableShares = new ArrayList<>(numSecrets);
                    for (int i = 0; i < numSecrets; ++i) {
                        verifiableShares.add(new LinkedList<>());
                    }
                    confidentialData = new byte[numSecrets][];
                    for (EncryptedConfidentialMessage confidentialMessage : msgList) {
                        EncryptedConfidentialData[] sharesI = confidentialMessage.getShares();
                        for (int j = 0; j < numSecrets; ++j) {
                            verifiableShares.get(j).add(sharesI[j].getShare());
                        }
                    }
                    for (int k = 0; k < numSecrets; ++k) {
                        LinkedList<EncryptedVerifiableShare> secretI = verifiableShares.get(k);
                        Share[] shares = new Share[secretI.size()];
                        Map<BigInteger, Commitment> commitmentsToCombine = new HashMap<>(secretI.size());
                        byte[] shareData = secretI.getFirst().getSharedData();
                        int l = 0;
                        for (EncryptedVerifiableShare verifiableShare : secretI) {
                            try {
                                shares[l] = new Share(verifiableShare.getShareholder(),
                                        confidentialityScheme.decryptShare(clientId, verifiableShare.getShare()));
                            } catch (SecretSharingException e) {
                                logger.error("Failed to decrypt share of {}", verifiableShare.getShareholder(), e);
                            }
                            commitmentsToCombine.put(verifiableShare.getShareholder(), verifiableShare.getCommitments());
                            ++l;
                        }
                        Commitment commitment = commitmentScheme.combineCommitments(commitmentsToCombine);
                        OpenPublishedShares secret = new OpenPublishedShares(shares, commitment, shareData);
                        try {
                            confidentialData[k] = confidentialityScheme.combine(secret);
                        } catch (SecretSharingException e) {
                            ExtractedResponse extractedResponse = new ExtractedResponse(plainData, confidentialData, e);
                            TOMMessage lastMsg = replies[lastReceived];
                            return new TOMMessage(lastMsg.getSender(), lastMsg.getSession(), lastMsg.getSequence(),
                                    lastMsg.getOperationId(), extractedResponse.serialize(), new byte[0],
                                    lastMsg.getViewID(), lastMsg.getReqType());
                        }
                    }
                }
                ExtractedResponse extractedResponse2 = new ExtractedResponse(plainData, confidentialData);
                TOMMessage lastMsg = replies[lastReceived];
                return new TOMMessage(lastMsg.getSender(), lastMsg.getSession(), lastMsg.getSequence(),
                        lastMsg.getOperationId(), extractedResponse2.serialize(), new byte[0], lastMsg.getViewID(),
                        lastMsg.getReqType());
            }
        }
        logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
        return null;
    }

    @Override
    public int compare(byte[] o1, byte[] o2) {
        EncryptedConfidentialMessage response1 = responses.computeIfAbsent(o1, EncryptedConfidentialMessage::deserialize);
        EncryptedConfidentialMessage response2 = responses.computeIfAbsent(o2, EncryptedConfidentialMessage::deserialize);
        if (response1 == null && response2 == null) {
            return 0;
        }
        if (response1 == null) {
            return 1;
        }
        if (response2 == null) {
            return -1;
        }
        int hash1 = responseHashes.computeIfAbsent(response1, EncryptedConfidentialMessage::hashCode);
        int hash2 = responseHashes.computeIfAbsent(response2, EncryptedConfidentialMessage::hashCode);
        return hash1 - hash2;
    }

    @Override
    public void reset() {
        responses.clear();
        responseHashes.clear();
    }
}
