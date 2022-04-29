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
package se.signatureservice.support.system;

import se.signatureservice.support.common.system.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Support service configuration. Contains all configuration parameters
 * that can be specified for each profile to control the signing process.
 *
 * Created by Tobias Agerberg on 24/05/17
 */
public final class SupportConfiguration extends Configuration {

    /**
     * The name of the related profile, set automatically by configuration manager.
     */
    private String relatedProfile;

    /**
     * XAdES Signature level.
     * Supported values: XML-NOT-ETSI, XAdES-BASELINE-B, XAdES-BASELINE-T,
     * XAdES-BASELINE-LT, XAdES-BASELINE-LTA
     */
    private String xadesSignatureLevel = "XAdES-BASELINE-B";

    /**
     * XAdES Signature packing setting.
     * Supported values: DETACHED, ENVELOPED, ENVELOPING
     */
    private String xadesSignaturePacking = "ENVELOPED";

    /**
     * XAdES canonicalization algorithm that will be used when
     * calculating digests for SignedInfo and SignedProperties structures
     */
    private String xadesCanonicalizationAlgorithmURI = "http://www.w3.org/2001/10/xml-exc-c14n#";

    /**
     * XAdES XPath location string that defines the area where
     * the signature will be added
     */
    private String xadesXPathLocationString = "node()[not(self::Signature)]";

    /**
     * PAdES Signature level.
     * Supported values: PDF-NOT-ETSI, PAdES-BASELINE-B, PAdES-BASELINE-T,
     * PAdES-BASELINE-LT, PAdES-BASELINE-LTA
     */
    private String padesSignatureLevel = "PAdES-BASELINE-B";

    /**
     * PaDES Signature packing setting.
     * Supported values: DETACHED, ENVELOPED, ENVELOPING
     */
    private String padesSignaturePacking = "ENVELOPED";

    /**
     * CAdES Signature level.
     * Supported values: CMS-NOT-ETSI, CAdES-BASELINE-B, CAdES-BASELINE-T,
     * CAdES-BASELINE-LT, CAdES-BASELINE-LTA
     */
    private String cadesSignatureLevel = "CAdES-BASELINE-B";

    /**
     * CAdES Signature packing setting.
     * Supported values: DETACHED, ENVELOPING
     */
    private String cadesSignaturePacking;

    /**
     * Overlap in minutes to overcome problems with time
     * synchronization. Signing certificate ValidFrom date will be set
     * to current time minus the specified overlap.
     */
    private int signatureValidityOverlapMinutes;

    /**
     * Signature certificate validity in minutes to request
     */
    private int signatureValidityMinutes;

    /**
     * Signature algorithm in Java-form to use.
     */
    private String signatureAlgorithm = "SHA256withRSA";

    /**
     * Algorithm schem to use when encrypting data. Used i.e. if encrypted sign
     * messages are enabled through the setting 'useEncryptedSignMessage'.
     * Available values: RSA_PKCS1_5_WITH_AES128, RSA_OAEP_WITH_AES128,
     * RSA_PKCS1_5_WITH_AES192, RSA_OAEP_WITH_AES192, RSA_PKCS1_5_WITH_AES256,
     * RSA_OAEP_WITH_AES256
     */
    private String encryptionAlgorithmScheme = "RSA_PKCS1_5_WITH_AES256";

    /**
     * Flag to choose if sign message should be encrypted or not. If this
     * is enabled the sign message will be encrypted using the public key
     * of the identity provider.
     */
    private boolean useEncryptedSignMessage = false;

    /**
     * Flag indicating if the sign message must be shown for a valid signature.
     */
    private boolean signMessageMustShow = false;

    /**
     * Mimetype of sign message.
     * Supported values: 'TEXT', 'HTML' or 'MARKDOWN'
     */
    private String signMessageMimeType = "TEXT";

    /**
     * SAML Attribute name that will map against user ID
     * @deprecated Use defaultUserIdAttributeMapping (since 2019-05-25).
     */
    private String userIdAttributeMapping;

    /**
     * SAML Attribute name that will map against user ID if
     * not specified in the identity provider configuration
     * (trustedAuthenticationServices).
     */
    private String defaultUserIdAttributeMapping;

    /**
     * User attribute key that will be used to fetch display name
     * of user to use when performing signatures. If this setting is missing
     * or if the specified attribute is missing the userId will be used.
     */
    private String userDisplayNameAttribute;

    /**
     * Time Stamp Server (TSA) to use. Required for all profiles except basic (B).
     */
    private String timeStampServer;

    /**
     * Signature service (frontend) SAML identity to specify in generated
     * EID Sign Requests (ex.https://esign.v2.st.signatureservice.se/signservice-frontend/metadata)
     */
    private String signServiceId;

    /**
     * Signature service (frontend) URL to redirect the user to with the
     * generated EID sign request (ex. https://esign.v2.st.signatureservice.se/signservice-frontend/request/4321a583928)
     */
    private String signServiceRequestURL;
    
    /**
     * Name of signature requesting entity/organisation.
     */
    private String signRequester;

    /**
     * Type/level of authentication to request in the signature process.
     * @deprecated Use defaultAuthnContextClassRef (since 2018-11-21).
     */
    @Deprecated
    private String authnContextClassRef;

    /**
     * Default Type/level of authentication to request in the signature process.
     */
    private String defaultAuthnContextClassRef;

    /**
     * List of default Types/levels of authentication to request in the signature process.
     */
    private List<String> defaultAuthnContextClassRefs;

    /**
     * Type of certificate to request in the signature process.
     * Supported values: PKC, QC, QC/SSCD
     */
    private String certificateType;

    /**
     * Map containing Requests for subject attributes in a signer
     * certificate that is associated with the signer of the generated
     * signature as a result of the sign request.
     *
     * Example configuration:
     * requestedCertAttributes {
     *     givenName {
     *         samlAttributeName = "urn:oid:2.5.4.42"
     *         certAttributeRef = "2.5.4.42"
     *         required = true
     *     }
     * }
     */
    private Map<String, Map> requestedCertAttributes;

    /**
     * Map containing attributes to be included in the signer element within the sign request,
     * in addition to the mandatory userId attribute (see defaultUserIdAttributeMapping) that
     * is always included as a signer attribute.
     *
     * For each entry the following configuration keys are used:
     *
     *   - samlAttributeName : The SAML attribute name to use for the signer attribute.
     *   - userAttributeMapping : User attribute key to look for when populating the signer attribute value.
     *   - required : If set to true the user given user attribute must exist, or an error is generated.
     *                If set to false the signer attribute is set only if the user attribute exists.
     *
     * Example configuration:
     * signerAttributes {
     *     orgAffiliation {
     *         samlAttributeName = "urn:oid:1.2.752.201.3.1"
     *         userAttributeMapping = "orgAffiliation"
     *         required = true
     *     }
     * }
     */
    private Map<String, Map> signerAttributes;

    /**
     * Map containing trusted authentication services/identity providers that
     * can be used for the given profile. Corresponding metadata for
     * each trusted service must also be available in the metadata directory.
     * Note: defaultDisplayName will be used if display name is not available in
     * metadata.
     *
     * Example configuration:
     * trustedAuthenticationServices {
     *     iDPTest {
     *         entityId = "https://idptest.someservice.se/samlv2/idp/metadata"
     *         defaultDisplayName = "Test iDP ST"
     *         authnContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
     *         userIdAttributeMapping = "urn:oid:1.2.752.29.4.13"
     *     }
     * }
     */
    private Map<String,Map> trustedAuthenticationServices;

    /**
     * Required setting containing the Meta Data Entity Id of all trusted central services that
     * might send signature responses to this support service.
     */
    private List<String> authorizedCentralServiceEntityIds;

    /**
     * Required setting containing a list of authorized consumer URLs that can be specified
     * by the driving application.
     */
    private List<String> authorizedConsumerURLs;

    /**
     * Validation policy to use when verifying signed documents. Policy file must be specified
     * using filename (with or without .xml extension) of policy file which must be present
     * in the policy directory specified by the application setting 'validation.policy.directory'.
     */
    private String validationPolicy;

    /**
     * Flag indicating if enhanced logging should be enabled or not. If enhanced logging is
     * enabled the following details will be written to the logfile using INFO-level:
     *
     * - Subject of certificate that was used for signing
     * - Signing time of document(s)
     * - Reference information of document(s) that were signed
     * - Name of document(s) that were signed
     * - Issuer of certificate that was used for signing
     * - Information about which authentication performed prior to signing (assurance level)
     * - Complete signature response received from central signature service during signature flow.
     *
     * NOTE: By enabling this feature sensitive information might be written to the logfile.
     */
    private boolean enableEnhancedLogging = false;

    /**
     * Flag indicating if AuthnProfile element should be used or not in the generated
     * sign request. If enable the AuthnProfile will be set to the related signature profile
     * that was being used when generating the signature request.
     */
    private boolean enableAuthnProfile = false;

    /**
     * Flag indicating if signed documents should be automatically validated before returned
     * from the support service. If enabled, validation information will be included in the response
     * from completeSignature API call.
     */
    private boolean enableAutomaticValidation = false;

    /**
     * Setting indicating the version that should be set in the SignRequestExtension. Default is "1.5" that
     * supports multiple authn context class references.
     */
    private String signRequestExtensionVersion = "1.5";

    /**
     * Flag to enable/disable visible signatures in signed PDF documents. Visible signatures
     * will only be included if all required attributes for visible signatures are included
     * in the "signatureAttributes" parameters in call to prepareSignature.
     */
    private boolean enableVisibleSignature = false;

    /**
     * Image path to use for visible signatures. If not set the default image will be used.
     */
    private String visibleSignatureImage = null;

    public String getRelatedProfile() {
        return relatedProfile;
    }

    public void setRelatedProfile(String relatedProfile) {
        this.relatedProfile = relatedProfile;
    }

    public String getXadesSignatureLevel() {
        return xadesSignatureLevel;
    }

    public void setXadesSignatureLevel(String xadesSignatureLevel) {
        this.xadesSignatureLevel = xadesSignatureLevel;
    }

    public String getXadesSignaturePacking() {
        return xadesSignaturePacking;
    }

    public void setXadesSignaturePacking(String xadesSignaturePacking) {
        this.xadesSignaturePacking = xadesSignaturePacking;
    }

    public String getXadesCanonicalizationAlgorithmURI() {
        return xadesCanonicalizationAlgorithmURI;
    }

    public void setXadesCanonicalizationAlgorithmURI(String xadesCanonicalizationAlgorithmURI) {
        this.xadesCanonicalizationAlgorithmURI = xadesCanonicalizationAlgorithmURI;
    }

    public String getXadesXPathLocationString() {
        return xadesXPathLocationString;
    }

    public void setXadesXPathLocationString(String xadesXPathLocationString) {
        this.xadesXPathLocationString = xadesXPathLocationString;
    }

    public String getPadesSignatureLevel() {
        return padesSignatureLevel;
    }

    public void setPadesSignatureLevel(String padesSignatureLevel) {
        this.padesSignatureLevel = padesSignatureLevel;
    }

    public String getPadesSignaturePacking() {
        return padesSignaturePacking;
    }

    public void setPadesSignaturePacking(String padesSignaturePacking) {
        this.padesSignaturePacking = padesSignaturePacking;
    }

    public String getCadesSignatureLevel() {
        return cadesSignatureLevel;
    }

    public void setCadesSignatureLevel(String cadesSignatureLevel) {
        this.cadesSignatureLevel = cadesSignatureLevel;
    }

    public String getCadesSignaturePacking() {
        return cadesSignaturePacking;
    }

    public void setCadesSignaturePacking(String cadesSignaturePacking) {
        this.cadesSignaturePacking = cadesSignaturePacking;
    }

    public int getSignatureValidityOverlapMinutes() {
        return signatureValidityOverlapMinutes;
    }

    public void setSignatureValidityOverlapMinutes(int signatureValidityOverlapMinutes) {
        this.signatureValidityOverlapMinutes = signatureValidityOverlapMinutes;
    }

    public int getSignatureValidityMinutes() {
        return signatureValidityMinutes;
    }

    public void setSignatureValidityMinutes(int signatureValidityMinutes) {
        this.signatureValidityMinutes = signatureValidityMinutes;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getEncryptionAlgorithmScheme() {
        return encryptionAlgorithmScheme;
    }

    public void setEncryptionAlgorithmScheme(String encryptionAlgorithmScheme) {
        this.encryptionAlgorithmScheme = encryptionAlgorithmScheme;
    }

    public boolean isUseEncryptedSignMessage() {
        return useEncryptedSignMessage;
    }

    public void setUseEncryptedSignMessage(boolean useEncryptedSignMessage) {
        this.useEncryptedSignMessage = useEncryptedSignMessage;
    }

    public boolean isSignMessageMustShow() {
        return signMessageMustShow;
    }

    public void setSignMessageMustShow(boolean signMessageMustShow) {
        this.signMessageMustShow = signMessageMustShow;
    }

    public String getSignMessageMimeType() {
        return signMessageMimeType;
    }

    public void setSignMessageMimeType(String signMessageMimeType) {
        this.signMessageMimeType = signMessageMimeType;
    }

    public String getUserIdAttributeMapping() {
        return userIdAttributeMapping;
    }

    public void setUserIdAttributeMapping(String userIdAttributeMapping) {
        this.userIdAttributeMapping = userIdAttributeMapping;
    }

    public String getDefaultUserIdAttributeMapping() {
        return defaultUserIdAttributeMapping;
    }

    public void setDefaultUserIdAttributeMapping(String defaultUserIdAttributeMapping) {
        this.defaultUserIdAttributeMapping = defaultUserIdAttributeMapping;
    }

    public String getUserDisplayNameAttribute() {
        return userDisplayNameAttribute;
    }

    public void setUserDisplayNameAttribute(String userDisplayNameAttribute) {
        this.userDisplayNameAttribute = userDisplayNameAttribute;
    }

    public String getTimeStampServer() {
        return timeStampServer;
    }

    public void setTimeStampServer(String timeStampServer) {
        this.timeStampServer = timeStampServer;
    }

    public String getSignServiceId() {
        return signServiceId;
    }

    public void setSignServiceId(String signServiceId) {
        this.signServiceId = signServiceId;
    }

    public String getSignServiceRequestURL() {
        return signServiceRequestURL;
    }

    public void setSignServiceRequestURL(String signServiceRequestURL) {
        this.signServiceRequestURL = signServiceRequestURL;
    }

    public String getSignRequester() {
        return signRequester;
    }

    public void setSignRequester(String signRequester) {
        this.signRequester = signRequester;
    }

    public String getAuthnContextClassRef() {
        return authnContextClassRef;
    }

    public void setAuthnContextClassRef(String authnContextClassRef) {
        this.authnContextClassRef = authnContextClassRef;
    }

    public String getDefaultAuthnContextClassRef() {
        return defaultAuthnContextClassRef;
    }

    public void setDefaultAuthnContextClassRef(String defaultAuthnContextClassRef) {
        this.defaultAuthnContextClassRef = defaultAuthnContextClassRef;
    }

    public List<String> getDefaultAuthnContextClassRefs() {
        return defaultAuthnContextClassRefs;
    }

    public void setDefaultAuthnContextClassRefs(List<String> defaultAuthnContextClassRefs) {
        this.defaultAuthnContextClassRefs = defaultAuthnContextClassRefs;
    }

    public String getCertificateType() {
        return certificateType;
    }

    public void setCertificateType(String certificateType) {
        this.certificateType = certificateType;
    }

    public Map<String, Map> getRequestedCertAttributes() {
        return requestedCertAttributes;
    }

    public void setRequestedCertAttributes(Map<String, Map> requestedCertAttributes) {
        this.requestedCertAttributes = requestedCertAttributes;
    }

    public Map<String, Map> getSignerAttributes() {
        return signerAttributes;
    }

    public void setSignerAttributes(Map<String, Map> signerAttributes) {
        this.signerAttributes = signerAttributes;
    }

    public Map<String, Map> getTrustedAuthenticationServices() {
        return trustedAuthenticationServices;
    }

    public void setTrustedAuthenticationServices(Map<String, Map> trustedAuthenticationServices) {
        this.trustedAuthenticationServices = trustedAuthenticationServices;
    }

    public List<String> getAuthorizedCentralServiceEntityIds() {
        return authorizedCentralServiceEntityIds;
    }

    public void setAuthorizedCentralServiceEntityIds(List<String> authorizedCentralServiceEntityIds) {
        this.authorizedCentralServiceEntityIds = authorizedCentralServiceEntityIds;
    }

    public List<String> getAuthorizedConsumerURLs() {
        return authorizedConsumerURLs;
    }

    public void setAuthorizedConsumerURLs(List<String> authorizedConsumerURLs) {
        this.authorizedConsumerURLs = authorizedConsumerURLs;
    }

    public String getValidationPolicy() {
        return validationPolicy;
    }

    public void setValidationPolicy(String validationPolicy) {
        this.validationPolicy = validationPolicy;
    }

    public boolean isEnableEnhancedLogging() {
        return enableEnhancedLogging;
    }

    public void setEnableEnhancedLogging(boolean enableEnhancedLogging) {
        this.enableEnhancedLogging = enableEnhancedLogging;
    }

    public boolean isEnableAuthnProfile() {
        return enableAuthnProfile;
    }

    public void setEnableAuthnProfile(boolean enableAuthnProfile) {
        this.enableAuthnProfile = enableAuthnProfile;
    }

    public boolean isEnableAutomaticValidation() {
        return enableAutomaticValidation;
    }

    public void setEnableAutomaticValidation(boolean enableAutomaticValidation) {
        this.enableAutomaticValidation = enableAutomaticValidation;
    }

    public String getSignRequestExtensionVersion() {
        return signRequestExtensionVersion;
    }

    public void setSignRequestExtensionVersion(String signRequestExtensionVersion) {
        this.signRequestExtensionVersion = signRequestExtensionVersion;
    }

    public boolean isEnableVisibleSignature() {
        return enableVisibleSignature;
    }

    public void setEnableVisibleSignature(boolean enableVisibleSignature) {
        this.enableVisibleSignature = enableVisibleSignature;
    }

    public String getVisibleSignatureImage() {
        return visibleSignatureImage;
    }

    public void setVisibleSignatureImage(String visibleSignatureImage) {
        this.visibleSignatureImage = visibleSignatureImage;
    }

    /**
     * Builder class to help when building a SupportConfiguration instance.
     */
    public static class Builder {
        private SupportConfiguration config;

        /**
         * Create new SupportConfiguration builder
         */
        public Builder(){
            config = new SupportConfiguration();
            config.setDefaultUserIdAttributeMapping(Constants.DEFAULT_USER_ID_ATTRIBUTE_MAPPING);
            config.setSignatureValidityMinutes(Constants.DEFAULT_REQUEST_VALIDITY_IN_MINUTES);
        }

        public Builder relatedProfile(String relatedProfile) {
            config.setRelatedProfile(relatedProfile);
            return this;
        }

        public Builder xadesSignatureLevel(String xadesSignatureLevel) {
            config.setXadesSignatureLevel(xadesSignatureLevel);
            return this;
        }

        public Builder xadesSignaturePacking(String xadesSignaturePacking) {
            config.setXadesSignaturePacking(xadesSignaturePacking);
            return this;
        }

        public Builder xadesCanonicalizationAlgorithmURI(String xadesCanonicalizationAlgorithmURI) {
            config.setXadesCanonicalizationAlgorithmURI(xadesCanonicalizationAlgorithmURI);
            return this;
        }

        public Builder xadesXPathLocationString(String xadesXPathLocationString) {
            config.setXadesXPathLocationString(xadesXPathLocationString);
            return this;
        }

        public Builder padesSignatureLevel(String padesSignatureLevel) {
            config.setPadesSignatureLevel(padesSignatureLevel);
            return this;
        }

        public Builder padesSignaturePacking(String padesSignaturePacking) {
            config.setPadesSignaturePacking(padesSignaturePacking);
            return this;
        }

        public Builder cadesSignatureLevel(String cadesSignatureLevel) {
            config.setCadesSignatureLevel(cadesSignatureLevel);
            return this;
        }

        public Builder cadesSignaturePacking(String cadesSignaturePacking) {
            config.setCadesSignaturePacking(cadesSignaturePacking);
            return this;
        }

        public Builder signatureValidityOverlapMinutes(int signatureValidityOverlapMinutes) {
            config.setSignatureValidityOverlapMinutes(signatureValidityOverlapMinutes);
            return this;
        }

        public Builder signatureValidityMinutes(int signatureValidityMinutes) {
            config.setSignatureValidityMinutes(signatureValidityMinutes);
            return this;
        }

        public Builder signatureAlgorithm(String signatureAlgorithm) {
            config.setSignatureAlgorithm(signatureAlgorithm);
            return this;
        }

        public Builder encryptionAlgorithmScheme(String encryptionAlgorithmScheme) {
            config.setEncryptionAlgorithmScheme(encryptionAlgorithmScheme);
            return this;
        }

        public Builder useEncryptedSignMessage(boolean useEncryptedSignMessage) {
            config.setUseEncryptedSignMessage(useEncryptedSignMessage);
            return this;
        }

        public Builder signMessageMustShow(boolean signMessageMustShow) {
            config.setSignMessageMustShow(signMessageMustShow);
            return this;
        }

        public Builder signMessageMimeType(String signMessageMimeType) {
            config.setSignMessageMimeType(signMessageMimeType);
            return this;
        }

        public Builder userIdAttributeMapping(String userIdAttributeMapping) {
            config.setUserIdAttributeMapping(userIdAttributeMapping);
            return this;
        }

        public Builder defaultUserIdAttributeMapping(String defaultUserIdAttributeMapping) {
            config.setDefaultUserIdAttributeMapping(defaultUserIdAttributeMapping);
            return this;
        }

        public Builder userDisplayNameAttribute(String userDisplayNameAttribute) {
            config.setUserDisplayNameAttribute(userDisplayNameAttribute);
            return this;
        }

        public Builder timeStampServer(String timeStampServer) {
            config.setTimeStampServer(timeStampServer);
            return this;
        }

        public Builder signServiceId(String signServiceId) {
            config.setSignServiceId(signServiceId);
            return this;
        }

        public Builder signServiceRequestURL(String signServiceRequestURL) {
            config.setSignServiceRequestURL(signServiceRequestURL);
            return this;
        }

        public Builder signRequester(String signRequester) {
            config.setSignRequester(signRequester);
            return this;
        }

        public Builder defaultAuthnContextClassRef(String defaultAuthnContextClassRef) {
            config.setDefaultAuthnContextClassRef(defaultAuthnContextClassRef);
            return this;
        }

        public Builder defaultAuthnContextClassRefs(List<String> defaultAuthnContextClassRefs) {
            config.setDefaultAuthnContextClassRefs(defaultAuthnContextClassRefs);
            return this;
        }

        public Builder addDefaultAuthnContextClassRef(String defaultAuthnContextClassRef) {
            List<String> refs = config.getDefaultAuthnContextClassRefs();
            if(refs == null){
                refs = new ArrayList<>();
            }
            refs.add(defaultAuthnContextClassRef);
            config.setDefaultAuthnContextClassRefs(refs);
            return this;
        }

        public Builder certificateType(String certificateType) {
            config.setCertificateType(certificateType);
            return this;
        }

        public Builder requestedCertAttributes(Map<String, Map> requestedCertAttributes) {
            config.setRequestedCertAttributes(requestedCertAttributes);
            return this;
        }

        public Builder addRequestedCertAttribute(String name, String samlAttributeName, String certAttributeRef, boolean required) {
            return addRequestedCertAttribute(name, samlAttributeName, certAttributeRef, null, required);
        }

        public Builder addRequestedCertAttribute(String name, String samlAttributeName, String certAttributeRef, String certNameType, boolean required) {
            Map<String,Map> certAttributes = config.getRequestedCertAttributes();
            if(certAttributes == null){
                certAttributes = new HashMap<>();
            }

            Map<String,String> newAttribute = new HashMap<>();
            newAttribute.put("samlAttributeName", samlAttributeName);
            newAttribute.put("certAttributeRef", certAttributeRef);
            if(certNameType != null) {
                newAttribute.put("certNameType", certNameType);
            }
            newAttribute.put("required", Boolean.toString(required));
            certAttributes.put(name, newAttribute);

            config.setRequestedCertAttributes(certAttributes);
            return this;
        }

        public Builder signerAttributes(Map<String, Map> signerAttributes) {
            config.setSignerAttributes(signerAttributes);
            return this;
        }

        public Builder addSignerAttribute(String name, String samlAttributeName, String userAttributeMapping, boolean required) {
            Map<String,Map> signerAttributes = config.getSignerAttributes();
            if(signerAttributes == null){
                signerAttributes = new HashMap<>();
            }

            Map<String,String> newAttribute = new HashMap<>();
            newAttribute.put("samlAttributeName", samlAttributeName);
            newAttribute.put("userAttributeMapping", userAttributeMapping);
            newAttribute.put("required", Boolean.toString(required));
            signerAttributes.put(name, newAttribute);

            config.setRequestedCertAttributes(signerAttributes);
            return this;
        }

        public Builder trustedAuthenticationServices(Map<String, Map> trustedAuthenticationServices) {
            config.setTrustedAuthenticationServices(trustedAuthenticationServices);
            return this;
        }

        public Builder addTrustedAuthenticationService(String name, String entityId, String defaultDisplayName) {
            return addTrustedAuthenticationService(name, entityId, defaultDisplayName, (List<String>)null, null);
        }

        public Builder addTrustedAuthenticationService(String name, String entityId, String defaultDisplayName, String authnContextClassRef, String userIdAttributeMapping) {
            List<String> refs = new ArrayList<>();
            if(authnContextClassRef != null){
                refs.add(authnContextClassRef);
            }
            return addTrustedAuthenticationService(name, entityId, defaultDisplayName, authnContextClassRef, userIdAttributeMapping);
        }

        public Builder addTrustedAuthenticationService(String name, String entityId, String defaultDisplayName, List<String> authnContextClassRefs, String userIdAttributeMapping) {
            Map<String,Map> trustedServices = config.getTrustedAuthenticationServices();
            if(trustedServices == null){
                trustedServices = new HashMap<>();
            }

            Map<String,Object> newService = new HashMap<>();
            newService.put("entityId", entityId);
            newService.put("defaultDisplayName", defaultDisplayName);

            if(authnContextClassRefs != null){
                if(authnContextClassRefs.size() > 1){
                    newService.put("authnContextClassRefs", authnContextClassRefs);
                } else {
                    newService.put("authnContextClassRef", authnContextClassRefs.get(0));
                }
            }

            if(userIdAttributeMapping != null){
                newService.put("userIdAttributeMapping", userIdAttributeMapping);
            }

            trustedServices.put(name, newService);
            config.setTrustedAuthenticationServices(trustedServices);
            return this;
        }

        public Builder authorizedCentralServiceEntityIds(List<String> authorizedCentralServiceEntityIds) {
            config.setAuthorizedCentralServiceEntityIds(authorizedCentralServiceEntityIds);
            return this;
        }

        public Builder addAuthorizedCentralServiceEntityId(String authorizedCentralServiceEntityId) {
            List<String> entityIds = config.getAuthorizedCentralServiceEntityIds();
            if(entityIds == null){
                entityIds = new ArrayList<>();
            }
            entityIds.add(authorizedCentralServiceEntityId);
            config.setAuthorizedCentralServiceEntityIds(entityIds);
            return this;
        }

        public Builder authorizedConsumerURLs(List<String> authorizedConsumerURLs) {
            config.setAuthorizedConsumerURLs(authorizedConsumerURLs);
            return this;
        }

        public Builder addAuthorizedConsumerURL(String authorizedConsumerURL) {
            List<String> urls = config.getAuthorizedConsumerURLs();
            if(urls == null){
                urls = new ArrayList<>();
            }
            urls.add(authorizedConsumerURL);
            config.setAuthorizedConsumerURLs(urls);
            return this;
        }

        public Builder validationPolicy(String validationPolicy) {
            config.setValidationPolicy(validationPolicy);
            return this;
        }

        public Builder enableEnhancedLogging(boolean enableEnhancedLogging) {
            config.setEnableEnhancedLogging(enableEnhancedLogging);
            return this;
        }

        public Builder enableAuthnProfile(boolean enableAuthnProfile) {
            config.setEnableAuthnProfile(enableAuthnProfile);
            return this;
        }

        public Builder enableAutomaticValidation(boolean enableAutomaticValidation) {
            config.setEnableAutomaticValidation(enableAutomaticValidation);
            return this;
        }

        public Builder signRequestExtensionVersion(String signRequestExtensionVersion) {
            config.setSignRequestExtensionVersion(signRequestExtensionVersion);
            return this;
        }

        public Builder enableVisibleSignature(boolean enableVisibleSignature) {
            config.setEnableVisibleSignature(enableVisibleSignature);
            return this;
        }

        public Builder visibleSignatureImage(String visibleSignatureImage) {
            config.setVisibleSignatureImage(visibleSignatureImage);
            return this;
        }

        /**
         * Build the SupportConfiguration instance.
         *
         * @return SupportConfiguration instance based on builder settings.
         */
        public SupportConfiguration build() {
            return config;
        }
    }
}
