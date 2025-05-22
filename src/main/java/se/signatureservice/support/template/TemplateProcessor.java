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

import java.util.Map;

/**
 * Template processor used in order to populate a template
 * string using a set of given values.
 *
 * @author Tobias Agerberg
 */
public interface TemplateProcessor {

    /**
     * Populate template string with a map of given values in order to
     * produce a resulting string where template variables have been
     * replaced by actual values.
     *
     * @param template Template string to populate.
     * @param values Value map to use when populating the template.
     * @return Given template string with variables populated by given values.
     */
    String populateTemplate(String template, Map<String, String> values);
}
