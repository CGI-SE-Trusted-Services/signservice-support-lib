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

import java.util.List;

/**
 * Class containing supported signature attributes that can be used
 * when processing signatures.
 */
public class AvailableSignatureAttributes {

    /**
     * x position of the visible signature
     */
    public static final String VISIBLE_SIGNATURE_POSITION_X = "visible_signature_position_x";

    /**
     * y position of the visible signature
     */
    public static final String VISIBLE_SIGNATURE_POSITION_Y = "visible_signature_position_y";

    /**
     * visible signature's width
     */
    public static final String VISIBLE_SIGNATURE_WIDTH      = "visible_signature_width";

    /**
     * visible signature's height
     */
    public static final String VISIBLE_SIGNATURE_HEIGHT     = "visible_signature_height";

    /**
     * which page to put the visible signature
     */
    public static final String VISIBLE_SIGNATURE_PAGE       = "visible_signature_page";

    /**
     * Default value for visible signature X-position
     */
    public static final String DEFAULT_VISIBLE_SIGNATURE_POSITION_X = "20";

    /**
     * Default value for visible signature Y-position
     */
    public static final String DEFAULT_VISIBLE_SIGNATURE_POSITION_Y = "20";

    /**
     * Default value for visible signature width
     */
    public static final String DEFAULT_VISIBLE_SIGNATURE_WIDTH = "0";

    /**
     * Default value for visible signature height
     */
    public static final String DEFAULT_VISIBLE_SIGNATURE_HEIGHT = "0";

    /**
     * Default value for visible signature page
     */
    public static final String DEFAULT_VISIBLE_SIGNATURE_PAGE = "1";

    /**
     * ServiceName
     */
    public static final String ATTRIBUTE_SERVICE_NAME = "service_name";

    /**
     * AuthContextClassRef
     */
    public static final String ATTRIBUTE_AUTH_CONTEXT_CLASS_REF = "auth_context_class_ref";

    /**
     * SignServiceRequestURL
     */
    public static final String ATTRIBUTE_SIGNSERVICE_REQUEST_URL = "signservice_request_url";

    /**
     * Help method to fetch signer attribute value where keys is treated case-insensitive.
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
}
