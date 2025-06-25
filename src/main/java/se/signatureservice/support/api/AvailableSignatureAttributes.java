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
package se.signatureservice.support.api;

import se.signatureservice.support.api.v2.Attribute;

import java.util.ArrayList;
import java.util.List;

/**
 * Class containing supported signature attributes that can be used
 * when processing signatures.
 */
public class AvailableSignatureAttributes {

    /**
     * X-position of the visible signature.
     */
    public static final String VISIBLE_SIGNATURE_POSITION_X = "visible_signature_position_x";

    /**
     * Y-position of the visible signature.
     */
    public static final String VISIBLE_SIGNATURE_POSITION_Y = "visible_signature_position_y";

    /**
     * Visible signature's width.
     */
    public static final String VISIBLE_SIGNATURE_WIDTH      = "visible_signature_width";

    /**
     * Visible signature's height.
     */
    public static final String VISIBLE_SIGNATURE_HEIGHT     = "visible_signature_height";

    /**
     * Which page to put the visible signature on.
     */
    public static final String VISIBLE_SIGNATURE_PAGE       = "visible_signature_page";

    /**
     * Image data (as Base64-encoded string) to display within the visible signature. If this
     * attribute is specified it overrides any logoImage specified in configuration.
     */
    public static final String VISIBLE_SIGNATURE_LOGO_IMAGE = "visible_signature_logo_image";

    /**
     * ServiceName.
     */
    public static final String ATTRIBUTE_SERVICE_NAME = "service_name";

    /**
     * Preferred Lang.
     */
    public static final String ATTRIBUTE_PREFERRED_LANG = "preferred_lang";

    /**
     * AuthContextClassRef
     */
    public static final String ATTRIBUTE_AUTH_CONTEXT_CLASS_REF = "auth_context_class_ref";

    /**
     * SignServiceRequestURL
     */
    public static final String ATTRIBUTE_SIGNSERVICE_REQUEST_URL = "signservice_request_url";

    /**
     * Default value for visible signature X-position.
     */
    public static final String DEFAULT_VISIBLE_SIGNATURE_POSITION_X = "20";

    /**
     * Default value for visible signature Y-position.
     */
    public static final String DEFAULT_VISIBLE_SIGNATURE_POSITION_Y = "20";

    /**
     * Default value for visible signature width.
     */
    public static final String DEFAULT_VISIBLE_SIGNATURE_WIDTH = "0";

    /**
     * Default value for visible signature height.
     */
    public static final String DEFAULT_VISIBLE_SIGNATURE_HEIGHT = "0";

    /**
     * Default value for visible signature page.
     */
    public static final String DEFAULT_VISIBLE_SIGNATURE_PAGE = "1";

    /**
     * Array of signature attributes that are allowed to be specified per document.
     */
    private static final List<String> ALLOWED_PER_DOCUMENT_ATTRIBUTES = registerAllowedPerDocumentAttributes();

    /**
     * Help method to fetch signer attribute value where keys is treated case-insensitive.
     *
     * @param signatureAttributes list of signature attributes.
     * @param attributeKey the attribute key to lookup.
     * @return value of null if no such attribute where set.
     */
    public static String getAttributeValue(List<Attribute> signatureAttributes, String attributeKey) {
        if (signatureAttributes == null || signatureAttributes.isEmpty() || attributeKey == null) {
            return null;
        }

        for (Attribute attribute : signatureAttributes) {
            if (attribute != null && attribute.getKey().equalsIgnoreCase(attributeKey)) {
                return attribute.getValue();
            }
        }
        return null;
    }

    /**
     * Check if an attribute is allowed to be specified per document or not.
     *
     * @param attribute Attribut to check.
     * @return true if attribute is allowed to be specified per document, otherwise false.
     */
    public static boolean isAllowedPerDocument(String attribute){
        return ALLOWED_PER_DOCUMENT_ATTRIBUTES.contains(attribute);
    }

    /**
     * Return list of signature attributes that are allowed to be specified per-document.
     *
     * @return List of allowed attributes.
     */
    private static List<String> registerAllowedPerDocumentAttributes(){
        List<String> allowedAttributes = new ArrayList<>();
        allowedAttributes.add(VISIBLE_SIGNATURE_POSITION_X);
        allowedAttributes.add(VISIBLE_SIGNATURE_POSITION_Y);
        allowedAttributes.add(VISIBLE_SIGNATURE_WIDTH);
        allowedAttributes.add(VISIBLE_SIGNATURE_HEIGHT);
        allowedAttributes.add(VISIBLE_SIGNATURE_PAGE);
        allowedAttributes.add(VISIBLE_SIGNATURE_LOGO_IMAGE);
        return allowedAttributes;
    }
}
