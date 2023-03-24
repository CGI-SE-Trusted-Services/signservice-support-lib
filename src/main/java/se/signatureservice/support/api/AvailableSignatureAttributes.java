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
}
