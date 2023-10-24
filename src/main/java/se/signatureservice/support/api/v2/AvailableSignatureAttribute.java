package se.signatureservice.support.api.v2;

import java.util.List;

/**
 * TODO Filip
 */
public class AvailableSignatureAttribute {

    public static final String ATTRIBUTE_AUTHCONTEXTCLASSREF = "AUTHCONTEXTCLASSREF";

    /**
     * TODO Filip unit tests
     * Help method to fetch signer attribute value where keys is treated case-insensitve.
     * @param signatureAttributes list of signature attributes.
     * @param attributeKey the attribute key to lookup
     * @return value of null if no such attribute where set.
     */
    public static String getAttributeValue(List<Attribute> signatureAttributes, String attributeKey){
        if(signatureAttributes != null){
            for(Attribute attribute : signatureAttributes){
                if(attribute.getKey().toUpperCase().equals(attributeKey)){
                    return attribute.getValue();
                }
            }
        }
        return null;
    }
}
