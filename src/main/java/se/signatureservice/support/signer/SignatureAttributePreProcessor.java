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
package se.signatureservice.support.signer;

import se.signatureservice.support.api.v2.Attribute;
import se.signatureservice.support.api.v2.DocumentSigningRequest;

import java.util.List;

/**
 * Interface describing a signature attribute pre-processor that can perform any
 * needed pre-processing of attributes before they are being used during document
 * signing.
 *
 * @author Tobias Agerberg
 */
public interface SignatureAttributePreProcessor {

    /**
     * Perform pre-processing of signature attributes before the attributes are
     * being used during document signing.
     *
     * IMPORTANT: This function must return a copy of the given attributes, since
     * the same list of signature attributes is used for each document during batch
     * signing and pre-processed attributes are related to a specific document.
     *
     * @param signatureAttributes Signature attributes to pre-process.
     * @param document Document related to the signature attributes.
     * @return List of pre-processed attributes to be used during document signing for the given document.
     */
    List<Attribute> preProcess(final List<Attribute> signatureAttributes, DocumentSigningRequest document);
}
