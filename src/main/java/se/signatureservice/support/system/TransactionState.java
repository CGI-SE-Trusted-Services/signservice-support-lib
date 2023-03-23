/************************************************************************
 *                                                                       *
 *  Signservice Support Lib                                              *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  (LGPL-3.0-or-later)                                                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.system;

import se.signatureservice.support.api.v2.DocumentRequests;
import se.signatureservice.support.api.v2.User;
import se.signatureservice.support.utils.SerializableUtils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Serializable class containing all information needed to describe
 * the state of a transaction. This is the information that is kept
 * in cache during a transaction flow.
 *
 * @author Tobias Agerberg
 */
public class TransactionState implements Externalizable {
    static final long serialVersionUID = 1L;

    /**
     * The latest version of persisted data. Should be update for every change in the stored
     * data.
     */
    private static final int LATEST_VERSION = 1;

    /**
     * The transaction id to be used if same id should be used in
     * log files within the entire signature flow. both calling application
     * and signature service application.
     */
    private String transactionId;

    /**
     * The related profile used for the signature. A profile defines a configured
     * workflow inside the server.
     */
    private String profile;

    /**
     * Sign message shown prompted to the end user before signing. If sign message
     * is used is depending on profile configuration.
     */
    private String signMessage;

    /**
     * The id of the authentication service used (Usually the entity id of the selected IDP).
     * It is possible to get a list of available authentication services for a given profile
     * using the call GetAuthenticationServices.
     */
    private String authenticationServiceId;

    /**
     * The id and meta data of the end user that should sign the document
     * a User data structure defined below.
     */
    private User user;

    /**
     * A list of DocumentRequest (or DocumentRef if document should be fetched from archive)
     * containing document data about to be signed. If given profile supports counter
     * signatures is the same operation used again.
     */
    private DocumentRequests documents;

    /**
     * A map of signing time for each document signed within the transaction.
     * (key = <document reference>, value = (signing time>).
     */
    private Map<String, Date> signingTime = new HashMap<>();

    /**
     *  Transaction start time represented as the number of milliseconds
     *  since epoch (Midnight January 1, 1970 UTC).
     */
    private long transactionStart;

    /**
     * Flag indicating if this transaction has been completed or not.
     * With completed means that a call to completeSignature has been performed.
     */
    private boolean completed;

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getSignMessage() {
        return signMessage;
    }

    public void setSignMessage(String signMessage) {
        this.signMessage = signMessage;
    }

    public String getAuthenticationServiceId() {
        return authenticationServiceId;
    }

    public void setAuthenticationServiceId(String authenticationServiceId) {
        this.authenticationServiceId = authenticationServiceId;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public DocumentRequests getDocuments() {
        return documents;
    }

    public void setDocuments(DocumentRequests documents) {
        this.documents = documents;
    }

    public Map<String, Date> getSigningTime() {
        return signingTime;
    }

    public void setSigningTime(Map<String, Date> signingTime) {
        this.signingTime = signingTime;
    }

    public long getTransactionStart() {
        return transactionStart;
    }

    public void setTransactionStart(long transactionStart) {
        this.transactionStart = transactionStart;
    }

    public boolean isCompleted() {
        return completed;
    }

    public void setCompleted(boolean completed) {
        this.completed = completed;
    }

    /**
     * Serialize object and writing its content to stream
     *
     * @param output the stream to write the object to
     * @exception IOException Includes any I/O exceptions that may occur
     */
    @Override
    public void writeExternal(ObjectOutput output) throws IOException {
        output.writeInt(LATEST_VERSION);
        SerializableUtils.serializeNullableString(output, transactionId);
        SerializableUtils.serializeNullableString(output, profile);
        SerializableUtils.serializeNullableString(output, signMessage);
        SerializableUtils.serializeNullableString(output, authenticationServiceId);
        SerializableUtils.serializeNullableObject(output, user);
        SerializableUtils.serializeNullableObject(output, documents);
        if(signingTime != null){
            output.writeInt(signingTime.size());
            for(Map.Entry<String,Date> entry : signingTime.entrySet()){
                SerializableUtils.serializeNullableString(output, entry.getKey());
                SerializableUtils.serializeNullableDate(output, entry.getValue());
            }
        } else {
            output.writeInt(-1);
        }
        output.writeLong(transactionStart);
        output.writeBoolean(completed);
    }

    /**
     * Deserialize object through data from stream
     *
     * @param input the stream to read data from in order to restore the object
     * @exception IOException if I/O errors occur
     * @exception ClassNotFoundException If the class for an object being
     *              restored cannot be found.
     */
    @Override
    public void readExternal(ObjectInput input) throws IOException, ClassNotFoundException {
        int ver = input.readInt();
        transactionId = SerializableUtils.deserializeNullableString(input);
        profile = SerializableUtils.deserializeNullableString(input);
        signMessage = SerializableUtils.deserializeNullableString(input);
        authenticationServiceId = SerializableUtils.deserializeNullableString(input);
        user = (User) SerializableUtils.deserializeNullableObject(input);
        documents = (DocumentRequests) SerializableUtils.deserializeNullableObject(input);
        signingTime = new HashMap<>();
        int size = input.readInt();
        for(int i=0;i<size;i++){
            signingTime.put(SerializableUtils.deserializeNullableString(input), SerializableUtils.deserializeNullableDate(input));
        }
        transactionStart = input.readLong();
        completed = input.readBoolean();
    }
}
