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
package se.signatureservice.support.api;

import se.signatureservice.support.api.v2.*;
import se.signatureservice.support.system.SupportConfiguration;

import java.util.List;

/**
 * Support service Java API to generate signature requests and to
 * process signature responses in order to produce signed documents.
 *
 * @author Tobias Agerberg
 */
public interface SupportServiceAPI {

    /**
     * Generate signature request info that contains the signature request
     * along with the transaction state that needs to be persisted and supplied
     * to processSignResponse in order to obtain the final signed document(s).
     *
     * @param profileConfig Profile configuration containing various settings to control how the signature request is generated.
     * @param documents Documents to generate sign request for.
     * @param transactionId Transaction ID to use or null to let the library generate one automatically.
     * @param signMessage Signature message to include in the request or null if no signature message should be used.
     * @param user Information about the signatory.
     * @param authenticationServiceId Authentication service (identity provider) to use when signing the document.
     * @param consumerURL Return URL that the user should be redirected to in the end of the signature flow.
     * @param signatureAttributes Optional attributes to use.
     * @return SignRequestInfo instance that contains the XML signature request along with the transaction state.
     * @throws ClientErrorException If an error occurred when generating the signature request due to client supplied data.
     * @throws ServerErrorException If an internal error occurred when generating the signature request.
     */
    PreparedSignatureResponse prepareSignature(
            SupportConfiguration profileConfig,
            DocumentRequests documents,
            String transactionId,
            String signMessage,
            User user,
            String authenticationServiceId,
            String consumerURL,
            List<Attribute> signatureAttributes
    ) throws ClientErrorException, ServerErrorException;

    /**
     * Process a signature response along with the transaction state in order to compile
     * a complete signature response containing signed document(s).
     *
     * @param signResponse Signature response to process.
     * @param transactionState Related transaction state given by the initial call to generateSignRequest.
     * @return CompleteSignatureResponse that contains the signed document(s).
     * @throws ClientErrorException If an error occurred when generating the signature request due to client supplied data.
     * @throws ServerErrorException If an internal error occurred when generating the signature request.
     */
    CompleteSignatureResponse completeSignature(
            String signResponse,
            byte[] transactionState
    ) throws ClientErrorException, ServerErrorException;
}
