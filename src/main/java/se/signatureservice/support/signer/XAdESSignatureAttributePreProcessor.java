/************************************************************************
 *                                                                       *
 *  Signature Service - Support Service Library                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.signer;

import se.signatureservice.support.api.v2.Attribute;
import se.signatureservice.support.api.v2.DocumentSigningRequest;

import java.util.List;

/**
 * Pre-processing of signature attributes for documents signed using XAdES
 * algorithm.
 *
 * @author Tobias Agerberg
 */
public class XAdESSignatureAttributePreProcessor extends BaseSignatureAttributePreProcessor {

    /**
     * Perform pre-processing of signature attributes.
     *
     * @param signatureAttributes Signature attributes to pre-process and update.
     * @param document            Document related to the signature attributes.
     */
    @Override
    protected void doPreProcess(List<Attribute> signatureAttributes, DocumentSigningRequest document) {

    }
}
