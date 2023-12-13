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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.signatureservice.support.api.v2.Attribute;
import se.signatureservice.support.api.v2.DocumentSigningRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Base class that all signature attribute pre-processors should extend, that ensures
 * that the signature attributes are pre-processed in the same way for different
 * implementations.
 *
 * @author Tobias Agerberg
 */
public abstract class BaseSignatureAttributePreProcessor implements SignatureAttributePreProcessor {
    private static final Logger log = LoggerFactory.getLogger(BaseSignatureAttributePreProcessor.class);

    /**
     * Perform pre-processing of signature attributes before the attributes are
     * being used during document signing. Returned list is based on a copy of the given
     * signature attributes.
     *
     * @param signatureAttributes Signature attributes to pre-process.
     * @param document            Document related to the signature attributes.
     * @return List of pre-processed attributes to be used during document signing for the given document.
     */
    @Override
    public List<Attribute> preProcess(List<Attribute> signatureAttributes, DocumentSigningRequest document) {
        List<Attribute> preProcessedAttributes = new ArrayList<>();

        if(signatureAttributes == null || signatureAttributes.isEmpty()){
            return signatureAttributes;
        }

        try {
            // Create a copy of the original signature attributes before pre-processing.
            for(Attribute attribute : signatureAttributes){
                Attribute preProcessedAttribute = new Attribute();
                preProcessedAttribute.setKey(attribute.getKey());
                preProcessedAttribute.setValue(attribute.getValue());
                preProcessedAttributes.add(preProcessedAttribute);
            }

            doPreProcess(preProcessedAttributes, document);
        } catch(Exception e){
            if(log.isDebugEnabled()){
                log.error("Failed to pre-process signature attributes: " + e.getMessage(), e);
            } else {
                log.error("Failed to pre-process signature attributes: " + e.getMessage());
            }
        }
        return preProcessedAttributes;
    }

    /**
     * Perform pre-processing of signature attributes.
     *
     * @param signatureAttributes Signature attributes to pre-process and update.
     * @param document Document related to the signature attributes.
     */
    protected abstract void doPreProcess(List<Attribute> signatureAttributes, DocumentSigningRequest document) throws IOException;
}
