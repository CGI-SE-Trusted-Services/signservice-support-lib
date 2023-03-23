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
package se.signatureservice.support.api;

import se.signatureservice.support.api.v2.*;
import se.signatureservice.support.system.SupportAPIProfile;

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
            SupportAPIProfile profileConfig,
            DocumentRequests documents,
            String transactionId,
            String signMessage,
            User user,
            String authenticationServiceId,
            String consumerURL,
            List<Attribute> signatureAttributes
    ) throws ClientErrorException, ServerErrorException;

    /**
     * Process sign response from central signature service and create a complete signature response.
     *
     * @param profileConfig Profile configuration containing various settings to control how the signature request is generated.
     * @param signResponse Signature response to process.
     * @param transactionId Transaction ID for signature to process
     * @return CompleteSignatureResponse that contains the signed document(s).
     * @throws ClientErrorException If an error occurred when generating the signature request due to client supplied data.
     * @throws ServerErrorException If an internal error occurred when generating the signature request.
     */
    CompleteSignatureResponse completeSignature(
            SupportAPIProfile profileConfig,
            String signResponse,
            String transactionId
    ) throws ClientErrorException, ServerErrorException;

    /**
     * Verify a signed document.
     *
     * @param profileConfig Profile configuration containing various settings to control how the document is verified.
     * @param signedDocument Signed document to verify.
     * @return VerifyDocumentResponse that contains the result of the verification.
     * @throws ClientErrorException If an error occurred when verifying the document due to client supplied data.
     * @throws ServerErrorException If an internal error occurred when verifying the document.
     */
    VerifyDocumentResponse verifyDocument(
            SupportAPIProfile profileConfig,
            Document signedDocument
    ) throws ClientErrorException, ServerErrorException;
}
