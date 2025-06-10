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
package se.signatureservice.support.template;

/**
 * Class containing available template variables that is supported
 * by the templating engine.
 *
 * @author Tobias Agerberg
 */
public class AvailableTemplateVariables {

    /**
     * Name or identifier of the signatory that signs the document,
     * depending on configuration and user attributes.
     */
    public static final String SIGNER_NAME = "signerName";

    /**
     * Time when the signature was performed. Format is depending
     * on the give configuration.
     */
    public static final String TIMESTAMP = "timestamp";

    /**
     * Headline read from visible signature configuration.
     */
    public static final String HEADLINE = "headline";

    /**
     * Variable prefix to use signature attribute value in template. Complete
     * variable name depends on signature attribute name, i.e. to use a
     * signature attribute with name "department" the following variable name
     * should be used: {signatureAttribute.department}
     */
    public static final String SIGNATURE_ATTRIBUTE_PREFIX = "signatureAttribute.";
}
