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

import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import org.certificateservices.messages.MessageSecurityProvider;
import org.springframework.context.MessageSource;
import se.signatureservice.configuration.common.cache.CacheProvider;
import se.signatureservice.configuration.support.system.Constants;

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
     * Certificate source to use during validation of documents
     * that contains trusted certificates.
     */
    private CertificateSource trustedCertificateSource;

    /**
     * If simple report should be generated during validation.
     * Default value: true
     */
    private boolean useSimpleValidationReport = true;

    /**
     * Proxy configuration to use during validation when fetching
     * revocation data or null if no proxy should be used.
     * Default value: null
     */
    private ProxyConfig validationProxyConfig = null;

    /**
     * How long in milliseconds that the revocation data cache is valid before
     * being refreshed.
     * Default value: 86400000 (24h)
     */
    private long validationCacheExpirationTimeMS = Constants.DEFAULT_VALIDATION_CACHE_EXPIRATION_TIME;

    /**
     * Map containing list of recipient certificates, for each authentication service
     * to use when creating encrypted sign messages.
     */
    private Map<String, List<X509Certificate>> encryptedSignMessageRecipients = new HashMap<>();

    /**
     * Map containing mappings between authentication contexts and level of assurance.
     */
    private Map<String, Map> authContextMappings = new HashMap<>();

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

    public CertificateSource getTrustedCertificateSource() {
        return trustedCertificateSource;
    }

    public void setTrustedCertificateSource(CertificateSource certificateSource) {
        this.trustedCertificateSource = certificateSource;
    }

    public boolean isUseSimpleValidationReport() {
        return useSimpleValidationReport;
    }

    public void setUseSimpleValidationReport(boolean useSimpleValidationReport) {
        this.useSimpleValidationReport = useSimpleValidationReport;
    }

    public long getValidationCacheExpirationTimeMS() {
        return validationCacheExpirationTimeMS;
    }

    public void setValidationCacheExpirationTimeMS(long validationCacheExpirationTimeMS) {
        this.validationCacheExpirationTimeMS = validationCacheExpirationTimeMS;
    }

    public Map<String, List<X509Certificate>> getEncryptedSignMessageRecipients() {
        return encryptedSignMessageRecipients;
    }

    public void setEncryptedSignMessageRecipients(Map<String, List<X509Certificate>> encryptedSignMessageRecipients) {
        this.encryptedSignMessageRecipients = encryptedSignMessageRecipients;
    }

    public ProxyConfig getValidationProxyConfig() {
        return validationProxyConfig;
    }

    public void setValidationProxyConfig(ProxyConfig validationProxyConfig) {
        this.validationProxyConfig = validationProxyConfig;
    }

    public Map<String, Map> getAuthContextMappings() {
        return authContextMappings;
    }

    public void setAuthContextMappings(Map<String, Map> authContextMappings) {
        this.authContextMappings = authContextMappings;
    }

    public MessageSource getMessageSource() {
        return messageSource;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }
}
