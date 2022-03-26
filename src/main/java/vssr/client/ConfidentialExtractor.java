package vssr.client;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.Extractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;
import vssr.ConfidentialData;
import vssr.ConfidentialMessage;
import vssr.ExtractedResponse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

public class ConfidentialExtractor implements Extractor {
    private final Logger logger;
    private final Map<Integer, LinkedList<ConfidentialMessage>> responses;
    
    public ConfidentialExtractor() {
        this.logger = LoggerFactory.getLogger("confidential");
        this.responses = new HashMap<>();
    }
    
    public TOMMessage extractResponse(TOMMessage[] tomMessages, int sameContent, int lastReceived) {
        responses.clear();
        for (TOMMessage msg : tomMessages) {
            if (msg != null) {
                ConfidentialMessage response = ConfidentialMessage.deserialize(msg.getContent());
                if (response == null) {
                    logger.warn("Something went wrong while deserializing response from {}", msg.getSender());
                }
                else {
                    int responseHash = response.hashCode();
                    logger.debug("Response from {} with hash {}: {}", msg.getSender(), responseHash, response);
                    if (!responses.containsKey(responseHash)) {
                        LinkedList<ConfidentialMessage> msgList = new LinkedList<>();
                        msgList.add(response);
                        responses.put(responseHash, msgList);
                    }
                    else {
                        responses.get(responseHash).add(response);
                    }
                }
            }
        }
        for (LinkedList<ConfidentialMessage> msgList : responses.values()) {
            if (msgList.size() == sameContent) {
                ConfidentialMessage firstMsg = msgList.getFirst();
                byte[] plainData = firstMsg.getPlainData();
                if (firstMsg.getShares() != null) {
                    int numSecrets = firstMsg.getShares().length;
                    ArrayList<LinkedList<VerifiableShare>> verifiableShares = new ArrayList<>(numSecrets);
                    for (int i = 0; i < numSecrets; ++i) {
                        verifiableShares.add(new LinkedList<>());
                    }
                    OpenPublishedShares[] secrets = new OpenPublishedShares[numSecrets];
                    for (ConfidentialMessage confidentialMessage : msgList) {
                        ConfidentialData[] sharesI = confidentialMessage.getShares();
                        for (int j = 0; j < numSecrets; ++j) {
                            verifiableShares.get(j).add(sharesI[j].getShare().getShareAtIndex(0));
                        }
                    }
                    for (int j = 0; j < numSecrets; ++j) {
                        LinkedList<VerifiableShare> secretI = verifiableShares.get(j);
                        Share[] shares = new Share[secretI.size()];
                        Commitment commitments = secretI.getFirst().getCommitments();
                        byte[] shareData = secretI.getFirst().getSharedData();
                        int k = 0;
                        for (VerifiableShare verifiableShare : secretI) {
                            shares[k++] = verifiableShare.getShare();
                        }
                        secrets[j] = new OpenPublishedShares(shares, commitments, shareData);
                    }
                }
                ExtractedResponse extractedResponse = new ExtractedResponse(plainData, null);
                TOMMessage lastMsg = tomMessages[lastReceived];
                return new TOMMessage(lastMsg.getSender(), lastMsg.getSession(), lastMsg.getSequence(),
                        lastMsg.getOperationId(), extractedResponse.serialize(), new byte[0],
                        lastMsg.getViewID(), lastMsg.getReqType());
            }
        }
        logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
        return null;
    }
}
