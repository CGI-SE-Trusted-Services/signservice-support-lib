/************************************************************************
 *                                                                       *
 *  Signature Service - Support Service Library                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.models;

import se.signatureservice.support.api.v2.PreparedSignatureResponse;

/**
 * Class to represent a signature request along with
 * its serialized transaction state.
 *
 * @author Tobias Agerberg
 */
public class PreparedSignatureInfo {
    private final PreparedSignatureResponse preparedSignature;
    private final byte[] transactionState;

    /**
     * Create SignRequestInfo instance.
     *
     * @param preparedSignature Prepared signature data.
     * @param transactionState Related transaction state.
     */
    public PreparedSignatureInfo(PreparedSignatureResponse preparedSignature, byte[] transactionState){
        this.preparedSignature = preparedSignature;
        this.transactionState = transactionState;
    }

    /**
     * Get signature request.
     *
     * @return Signature request in XML-format as a String.
     */
    public PreparedSignatureResponse getPreparedSignature(){
        return preparedSignature;
    }

    /**
     * Get transaction state.
     *
     * @return Transaction state related to the signature request.
     */
    public byte[] getTransactionState(){
        return transactionState;
    }
}
