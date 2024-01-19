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

import org.apache.pdfbox.pdmodel.PDDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.signatureservice.support.api.AvailableSignatureAttributes;
import se.signatureservice.support.api.v2.Attribute;
import se.signatureservice.support.api.v2.DocumentSigningRequest;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

/**
 * Pre-processing of signature attributes for documents signed using PAdES
 * algorithm.
 *
 * @author Tobias Agerberg
 */
public class PAdESSignatureAttributePreProcessor extends BaseSignatureAttributePreProcessor {
    private static final Logger log = LoggerFactory.getLogger(PAdESSignatureAttributePreProcessor.class);

    /**
     * Perform pre-processing of signature attributes.
     *
     * @param signatureAttributes Signature attributes to pre-process and update.
     * @param document            Document related to the signature attributes.
     */
    @Override
    protected void doPreProcess(List<Attribute> signatureAttributes, DocumentSigningRequest document) throws IOException {
        try (PDDocument pdDocument = PDDocument.load(document.getData())) {
            for (Attribute attribute : signatureAttributes) {
                if (Objects.equals(attribute.getKey(), AvailableSignatureAttributes.VISIBLE_SIGNATURE_PAGE)) {
                    if (Integer.parseInt(attribute.getValue()) > pdDocument.getNumberOfPages()) {
                        attribute.setValue(String.valueOf(pdDocument.getNumberOfPages()));
                    }
                }
            }
        }
    }
}
