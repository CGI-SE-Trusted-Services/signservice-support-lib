package se.signatureservice.support.system;

import org.certificateservices.messages.MessageSecurityProvider;
import org.springframework.context.MessageSource;
import se.signatureservice.support.common.cache.CacheProvider;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Support service API configuration. Contains all configuration parameters
 * that can be specified to control the API.
 *
 * @author Tobias Agerberg
 */
public class SupportAPIConfiguration {
    /**
     * Message security provider to use when signing requests and when
     * verifying responses from central system.
     */
    private MessageSecurityProvider messageSecurityProvider;

    /**
     * Cache provider to use when storing various state information during
     * a transaction flow.
     */
    private CacheProvider cacheProvider;

    /**
     * Path to trust store to use when validating signatures.
     */
    private String trustStorePath;

    /**
     * Password that protects the trust store.
     */
    private String trustStorePassword;

    /**
     * Trust store type. Supported values are "JKS" and "PKCS12".
     * Default value: JKS
     */
    private String trustStoreType = "JKS";

    /**
     * Policy file to use from the class path when validating documents.
     * Default value: /validationpolicy.xml
     */
    private String validationPolicy = "/validationpolicy.xml";

    /**
     * If strict validation should be performed when validating documents.
     * Default value: false
     */
    private boolean performStrictValidation = false;

    /**
     * If revocation check should be disabled when validating document signatures.
     * Default value: false
     */
    private boolean disableRevocationCheck = false;

    /**
     * Map containing list of recipient certificates, for each authentication service
     * to use when creating encrypted sign messages.
     */
    private Map<String, List<X509Certificate>> encryptedSignMessageRecipients = new HashMap<>();

    /**
     * Message source to use for internationalization of messages or null to use
     * default language.
     * Default value: null
     */
    private MessageSource messageSource = null;

    public MessageSecurityProvider getMessageSecurityProvider() {
        return messageSecurityProvider;
    }

    public void setMessageSecurityProvider(MessageSecurityProvider messageSecurityProvider) {
        this.messageSecurityProvider = messageSecurityProvider;
    }

    public CacheProvider getCacheProvider() {
        return cacheProvider;
    }

    public void setCacheProvider(CacheProvider cacheProvider) {
        this.cacheProvider = cacheProvider;
    }

    public String getTrustStorePath() {
        return trustStorePath;
    }

    public void setTrustStorePath(String trustStorePath) {
        this.trustStorePath = trustStorePath;
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }

    public String getTrustStoreType() {
        return trustStoreType;
    }

    public void setTrustStoreType(String trustStoreType) {
        this.trustStoreType = trustStoreType;
    }

    public String getValidationPolicy() {
        return validationPolicy;
    }

    public void setValidationPolicy(String validationPolicy) {
        this.validationPolicy = validationPolicy;
    }

    public boolean isPerformStrictValidation() {
        return performStrictValidation;
    }

    public void setPerformStrictValidation(boolean performStrictValidation) {
        this.performStrictValidation = performStrictValidation;
    }

    public boolean isDisableRevocationCheck() {
        return disableRevocationCheck;
    }

    public void setDisableRevocationCheck(boolean disableRevocationCheck) {
        this.disableRevocationCheck = disableRevocationCheck;
    }

    public Map<String, List<X509Certificate>> getEncryptedSignMessageRecipients() {
        return encryptedSignMessageRecipients;
    }

    public void setEncryptedSignMessageRecipients(Map<String, List<X509Certificate>> encryptedSignMessageRecipients) {
        this.encryptedSignMessageRecipients = encryptedSignMessageRecipients;
    }

    public MessageSource getMessageSource() {
        return messageSource;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }
}
