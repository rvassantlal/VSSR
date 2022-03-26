package vssr.benchmark;

import bftsmart.tom.ServiceProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentUtils;
import vss.commitment.constant.ConstantCommitment;
import vss.facade.SecretSharingException;
import vssr.*;
import vssr.client.ClientConfidentialityScheme;
import vssr.client.Response;
import vssr.client.ServersResponseHandler;
import vssr.encrypted.EncryptedShare;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class PreComputedProxy {
    private final Logger logger;
    final ServiceProxy service;
    private final ClientConfidentialityScheme confidentialityScheme;
    private final ServersResponseHandler serversResponseHandler;
    private byte[] orderedCommonData;
    private byte[] unorderedCommonData;
    Map<Integer, byte[]> privateData;
    private final boolean preComputed;
    private final boolean isLinearCommitmentScheme;

    PreComputedProxy(final int clientId) throws SecretSharingException {
        this.logger = LoggerFactory.getLogger("confidential");
        this.preComputed = false;
        if (Configuration.getInstance().useTLSEncryption()) {
            this.serversResponseHandler = new PreComputedPlainServersResponseHandler(false);
        }
        else {
            this.serversResponseHandler = new PreComputedEncryptedServersResponseHandler(clientId, false);
        }
        this.service = new ServiceProxy(clientId, null, this.serversResponseHandler, this.serversResponseHandler, null);
        this.confidentialityScheme = new ClientConfidentialityScheme(this.service.getViewManager().getCurrentView());
        this.serversResponseHandler.setClientConfidentialityScheme(this.confidentialityScheme);
        this.isLinearCommitmentScheme = this.confidentialityScheme.isLinearCommitmentScheme();
    }

    PreComputedProxy(int clientId, final byte[] unorderedCommonData, byte[] orderedCommonData,
                     Map<Integer, byte[]> privateData) throws SecretSharingException {
        this.logger = LoggerFactory.getLogger("confidential");
        this.preComputed = true;
        if (Configuration.getInstance().useTLSEncryption()) {
            this.serversResponseHandler = new PreComputedPlainServersResponseHandler(true);
        }
        else {
            this.serversResponseHandler = new PreComputedEncryptedServersResponseHandler(clientId, true);
        }
        this.service = new ServiceProxy(clientId, null, this.serversResponseHandler, this.serversResponseHandler, null);
        this.confidentialityScheme = new ClientConfidentialityScheme(this.service.getViewManager().getCurrentView());
        this.serversResponseHandler.setClientConfidentialityScheme(this.confidentialityScheme);
        this.isLinearCommitmentScheme = this.confidentialityScheme.isLinearCommitmentScheme();
        this.unorderedCommonData = unorderedCommonData;
        this.orderedCommonData = orderedCommonData;
        this.privateData = privateData;
    }

    Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        byte[] response;
        if (preComputed) {
            byte metadata = (byte)((privateData == null) ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = service.invokeOrdered(orderedCommonData, privateData, metadata);
        }
        else {
            VSSRPublishedShares[] shares = sharePrivateData(confidentialData);
            if (confidentialData != null && shares == null) {
                return null;
            }
            byte[] commonData = serializeCommonData(plainData, shares);
            if (commonData == null) {
                return null;
            }
            Map<Integer, byte[]> privateData = null;
            if (confidentialData != null) {
                int[] servers = service.getViewManager().getCurrentViewProcesses();
                privateData = new HashMap<>(servers.length);
                for (int server : servers) {
                    byte[] b = this.serializePrivateDataFor(server, shares);
                    privateData.put(server, b);
                }
            }
            byte metadata = (byte)((privateData == null) ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = service.invokeOrdered(commonData, privateData, metadata);
        }

        return this.preComputed ? null : this.composeResponse(response);
    }

    Response invokeUnordered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        byte[] response;
        if (preComputed) {
            byte metadata = (byte)((privateData == null) ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = service.invokeUnordered(unorderedCommonData, null, metadata);
        }
        else {
            VSSRPublishedShares[] shares = sharePrivateData(confidentialData);
            if (confidentialData != null && shares == null) {
                return null;
            }
            byte[] commonData = serializeCommonData(plainData, shares);
            if (commonData == null) {
                return null;
            }
            Map<Integer, byte[]> privateData = null;
            if (confidentialData != null) {
                int[] servers = service.getViewManager().getCurrentViewProcesses();
                privateData = new HashMap<>(servers.length);
                for (int server : servers) {
                    byte[] b = serializePrivateDataFor(server, shares);
                    privateData.put(server, b);
                }
            }
            byte metadata = (byte)((privateData == null) ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = service.invokeUnordered(commonData, privateData, metadata);
        }

        return preComputed ? null : composeResponse(response);
    }

    public void close() {
        service.close();
    }

    private Response composeResponse(byte[] response) throws SecretSharingException {
        if (response == null)
            return null;
        ExtractedResponse extractedResponse = ExtractedResponse.deserialize(response);
        if (extractedResponse == null)
            return null;
        if (extractedResponse.getThrowable() != null)
            throw extractedResponse.getThrowable();
        return new Response(extractedResponse.getPlainData(), extractedResponse.getConfidentialData());
    }

    byte[] serializePrivateDataFor(int server, VSSRPublishedShares[] shares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            if (shares != null) {
                BigInteger shareholder = this.confidentialityScheme.getShareholder(server);
                for (VSSRPublishedShares share : shares) {
                    EncryptedShare[] encryptedShares = share.getShareOf(shareholder);
                    for (EncryptedShare encryptedShare : encryptedShares) {
                        byte[] encryptedShareBytes = encryptedShare.getEncryptedShare();
                        out.writeInt((encryptedShareBytes == null) ? -1 : encryptedShareBytes.length);
                        if (encryptedShareBytes != null) {
                            out.write(encryptedShareBytes);
                        }
                        if (!isLinearCommitmentScheme) {
                            Commitment[] commitments = share.getCommitments();
                            for (Commitment c : commitments) {
                                ConstantCommitment commitment = (ConstantCommitment)c;
                                byte[] witness = commitment.getWitness(shareholder);
                                out.writeInt(witness.length);
                                out.write(witness);
                            }
                        }
                    }
                }
            }
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            this.logger.error("Occurred while composing request", e);
            return null;
        }
    }

    byte[] serializeCommonData(byte[] plainData, VSSRPublishedShares[] shares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte)MessageType.CLIENT.ordinal());
            out.writeInt((plainData == null) ? -1 : plainData.length);
            if (plainData != null) {
                out.write(plainData);
            }
            out.writeInt((shares == null) ? -1 : shares.length);
            if (shares != null) {
                for (VSSRPublishedShares share : shares) {
                    byte[] r = share.getR().toByteArray();
                    out.writeInt(r.length);
                    out.write(r);
                    byte[] sharedData = share.getSharedData();
                    Commitment[] commitments = share.getCommitments();
                    out.writeInt((sharedData == null) ? -1 : sharedData.length);
                    if (sharedData != null) {
                        out.write(sharedData);
                    }
                    out.writeInt(commitments.length);
                    for (Commitment commitment : commitments) {
                        if (isLinearCommitmentScheme) {
                            CommitmentUtils.getInstance().writeCommitment(commitment, out);
                        }
                        else {
                            byte[] c = ((ConstantCommitment)commitment).getCommitment();
                            out.writeInt(c.length);
                            out.write(c);
                        }
                    }
                }
            }
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Occurred while composing request", e);
            return null;
        }
    }

    VSSRPublishedShares[] sharePrivateData(byte[]... privateData) throws SecretSharingException {
        if (privateData == null) {
            return null;
        }
        VSSRPublishedShares[] result = new VSSRPublishedShares[privateData.length];
        for (int i = 0; i < privateData.length; ++i) {
            result[i] = confidentialityScheme.share(privateData[i]);
        }
        return result;
    }
}
