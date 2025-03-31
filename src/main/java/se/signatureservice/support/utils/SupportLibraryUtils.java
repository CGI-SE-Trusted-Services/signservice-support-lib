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
package se.signatureservice.support.utils;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Hex;
import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.MessageSecurityProvider;
import se.signatureservice.messages.SimpleMessageSecurityProvider;
import se.signatureservice.messages.authcontsaci1.AuthContSaciMessageParser;
import se.signatureservice.messages.authcontsaci1.jaxb.AttributeMappingType;
import se.signatureservice.messages.authcontsaci1.jaxb.SAMLAuthContextType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.signatureservice.configuration.support.system.Constants;
import se.signatureservice.support.api.ErrorCode;
import se.signatureservice.support.api.v2.*;
import se.signatureservice.support.system.SupportAPIConfiguration;
import se.signatureservice.support.system.SupportAPIProfile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/**
 * Utility methods that can be used when working with the
 * support service library.
 *
 * @author Tobias Agerberg
 */
public class SupportLibraryUtils {
    public static final String OID_AUTHCONTEXT_EXTENTION = "1.2.752.201.5.1";

    private static final Logger log = LoggerFactory.getLogger(SupportLibraryUtils.class);

    /**
     * Create a simple message security provider.
     *
     * @param keyStorePath Path to key store to use when signing requests.
     * @param keyStorePassword Password that protects the key store.
     * @param keyStoreAlias Alias to private key within key store to use.
     * @param trustStorePath Path to trust store to use when verifying responses.
     * @param trustStorePassword Password that protects the trust store.
     * @return SimpleMessageSecurityProvider based on given parameters.
     * @throws MessageProcessingException If an error occurred when creating the message provider.
     */
    public static MessageSecurityProvider createSimpleMessageSecurityProvider(String keyStorePath, String keyStorePassword, String keyStoreAlias, String trustStorePath, String trustStorePassword) throws MessageProcessingException {
        Properties properties = new Properties();
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_PATH, keyStorePath);
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_PASSWORD, keyStorePassword);
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_ALIAS, keyStoreAlias);
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_TRUSTKEYSTORE_PATH, trustStorePath);
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_TRUSTKEYSTORE_PASSWORD, trustStorePassword);
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_ENCRYPTION_ALGORITHM_SCHEME, "RSA_PKCS1_5_WITH_AES256");
        return new SimpleMessageSecurityProvider(properties);
    }

    /**
     * Generate a unique transaction ID that can be used to identify a particular
     * signature workflow.
     * @return a unique transaction ID
     */
    public static String generateTransactionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a unique reference ID that can be used to identify a particular
     * document during a transaction. This will also be used as ID for the
     * corresponding signtask.
     * @return a unique sign task ID
     */
    public static String generateReferenceId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a document reference ID strongly mapped to a particular transaction ID
     * to get a globally unique document reference ID for a particular transaction.
     * The strong reference ID is defined as SHA256(transactionId + referenceId)
     * represented as a lowercase hex-encoded string.
     *
     * @param transactionId Transaction ID in which the document is processed.
     * @param referenceId Reference ID of document.
     * @return Globally unique reference ID of a given document in a given transaction.
     * @throws ServerErrorException if an error occurred when calculating the strong reference ID.
     */
    public static String generateStrongReferenceId(String transactionId, String referenceId) throws ServerErrorException {
        if(transactionId == null || transactionId.isEmpty() || referenceId == null || referenceId.isEmpty()){
            throw (ServerErrorException)ErrorCode.INTERNAL_ERROR.toException("Transaction ID and/or reference ID is empty or null. Cannot calculate strong reference ID.");
        }

        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(transactionId.getBytes(StandardCharsets.UTF_8));
            messageDigest.update(referenceId.getBytes(StandardCharsets.UTF_8));
            return Hex.toHexString(messageDigest.digest()).toLowerCase();
        } catch(NoSuchAlgorithmException e) {
            throw (ServerErrorException)ErrorCode.INTERNAL_ERROR.toException("Failed to calculate strong reference ID: " + e.getMessage());
        }
    }

    /**
     * Get user ID from SAMLAuthContextType
     * @param authContext SAMLAuthContextType containing userId
     * @param config SupportConfiguration
     * @return User ID from SAMLAuthContextType
     */
    public static String getUserIdFromAuthContext(SAMLAuthContextType authContext, SupportAPIProfile config){
        if(config.getUserIdAttributeMapping() != null){
            log.warn("Profile configuration 'userIdAttributeMapping' is deprecated. Please remove it and use 'defaultUserIdAttributeMapping' instead.");
        }

        return getAttributeValueFromAuthContext(authContext, config.getDefaultUserIdAttributeMapping() != null ? config.getDefaultUserIdAttributeMapping() : config.getUserIdAttributeMapping());
    }

    /**
     * Get user display name from SAMLAuthContextType. If display name is not available given name
     * and surname is used as fallback.
     * @param authContext SAMLAuthContextType containing user display
     * @return User display from SAMLAuthContextType
     */
    public static String getDisplayNameFromAuthContext(SAMLAuthContextType authContext){
        String displayName = getAttributeValueFromAuthContext(authContext, Constants.SWE_EID_DSS_SAML_ATTRIBUTE_DISPLAYNAME);
        if(displayName == null){
            String givenName = getAttributeValueFromAuthContext(authContext, Constants.SWE_EID_DSS_SAML_ATTRIBUTE_GIVENNAME);
            String surName = getAttributeValueFromAuthContext(authContext, Constants.SWE_EID_DSS_SAML_ATTRIBUTE_SN);

            if(givenName != null && surName != null){
                displayName = givenName + " " + surName;
            } else {
                displayName = givenName;
            }
        }
        return displayName;
    }

    /**
     * Get level of assurance from a SAMLAuthContextType
     *
     * @param apiConfig API configuration
     * @param authContext SAMLAuthContextType to get level of assurance from
     * @return Level of assurance for given SAMLAuthContextType or null if not available
     */
    public static String getLevelOfAssuranceFromAuthContext(SupportAPIConfiguration apiConfig, SAMLAuthContextType authContext) throws ServerErrorException {
        String levelOfAssurance = null;

        if(apiConfig.getAuthContextMappings() == null) {
            throw (ServerErrorException)ErrorCode.INVALID_CONFIGURATION.toException("No mapping between authentication contexts and level of assurance have been added.");
        }

        if(authContext != null){
            String classRef = authContext.getAuthContextInfo().getAuthnContextClassRef();

            for(Map.Entry<String, Map> entry : apiConfig.getAuthContextMappings().entrySet()){
                for(Object object : entry.getValue().entrySet()){
                    if(object instanceof Map){
                        Map<String,String> mapping = (Map<String,String>)object;
                        if(mapping.get("context") != null){
                            levelOfAssurance = mapping.get("loa");
                            break;
                        }
                    }
                }

                if(levelOfAssurance != null){
                    break;
                }
            }

            if(levelOfAssurance == null){
                levelOfAssurance = classRef;
            }
        }
        return levelOfAssurance;
    }

    /**
     * Get value of an attribute within an SAMLAuthContextType
     * @param authContext SAMLAuthContextType to get attribute from
     * @param attributeName attribute name
     * @return Attribute value from given SAMLAuthContextType or null if not available
     */
    static String getAttributeValueFromAuthContext(SAMLAuthContextType authContext, String attributeName){
        String value = null;

        if(authContext != null){
            List<AttributeMappingType> attributes = authContext.getIdAttributes().getAttributeMapping();
            for(AttributeMappingType attribute : attributes){
                if(attribute.getAttribute().getName().equals(attributeName) && !attribute.getAttribute().getAttributeValue().isEmpty()){
                    value = attribute.getAttribute().getAttributeValue().get(0).toString();
                    break;
                }
            }
        }

        return value;
    }

    /**
     * Extract SAMLAuthContextType from a X509 Certificate issued by signature services.
     * @param messageParser Message parser to use
     * @param certificate Certificate to extract SAMLAuthContextType from
     * @return SAMLAuthContextType from given certificate or null if certificate does not contain one
     */
    public static SAMLAuthContextType getAuthContextFromCertificate(AuthContSaciMessageParser messageParser, X509Certificate certificate) throws IOException, MessageContentException, MessageProcessingException {
        String retval = null;
        byte[] extensionValue = certificate.getExtensionValue(OID_AUTHCONTEXT_EXTENTION);

        if(extensionValue != null){
            DEROctetString octetString = (DEROctetString)(new ASN1InputStream(new ByteArrayInputStream(extensionValue)).readObject());
            ASN1Sequence extSequence = (ASN1Sequence)(new ASN1InputStream(new ByteArrayInputStream(octetString.getOctets())).readObject());
            if(extSequence != null && extSequence.size() == 1){
                ASN1Sequence authContextSequence = (ASN1Sequence)extSequence.getObjectAt(0);
                if(authContextSequence.size() == 2){
                    retval = authContextSequence.getObjectAt(1).toString();
                }
            }

            if(retval != null){
                return messageParser.parse(retval.getBytes(StandardCharsets.UTF_8));
            }
        }

        return null;
    }

    /**
     * Generate HTML redirect page based on a {@link PreparedSignatureResponse}
     * @param preparedSignature Signature response to generate HTML redirect page for.
     * @return HTML redirect page.
     */
    public static String generateRedirectHtml(PreparedSignatureResponse preparedSignature){
        StringBuilder sb = new StringBuilder();
        sb.append("<html>\n");
		sb.append("<body onload=\"document.forms[0].submit()\">\n");
        sb.append("<center>Processing signature...</center>\n");
		sb.append("<form method=\"post\" action=\"").append(preparedSignature.getActionURL()).append("\" style=\"display: none;\">\n");
		sb.append("<input type=\"hidden\" name=\"RelayState\" value=\"").append(preparedSignature.getTransactionId()).append("\" />\n");
		sb.append("<input type=\"hidden\" name=\"EidSignRequest\" value=\"").append(preparedSignature.getSignRequest()).append("\" />\n");
		sb.append("<input type=\"submit\" value=\"Submit\" />\n");
		sb.append("</form>\n");
		sb.append("</body>\n");
		sb.append("</html>\n");
        return sb.toString();
    }
}
