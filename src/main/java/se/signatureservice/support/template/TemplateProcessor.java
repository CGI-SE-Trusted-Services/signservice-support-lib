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
