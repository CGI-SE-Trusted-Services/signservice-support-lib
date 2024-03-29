package se.signatureservice.support.template;

import java.util.Map;

/**
 * Default implementation of template processor to use when populating
 * templates within the library.
 *
 * Variables within the template string must be specified using curly
 * braces syntax (ex. {signerName}).
 *
 * @author Tobias Agerberg
 */
public class DefaultTemplateProcessor implements TemplateProcessor {

    /**
     * Populate template string with a map of given values in order to
     * produce a resulting string where template variables have been
     * replaced by actual values.
     *
     * @param template Template string to populate.
     * @param values   Value map to use when populating the template.
     * @return Given template string with variables populated by given values.
     */
    @Override
    public String populateTemplate(String template, Map<String, String> values) {
        if(values != null) {
            for (Map.Entry<String, String> entry : values.entrySet()) {
                String variableName = entry.getKey();
                String variableValue = entry.getValue();
                String dollarSignPattern = "\\{" + variableName + "\\}";
                template = template.replaceAll(dollarSignPattern, variableValue);
            }
        }
        return template;
    }
}
