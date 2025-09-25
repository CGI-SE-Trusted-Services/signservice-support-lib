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
package se.signatureservice.support.metadata;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import se.signatureservice.configuration.common.InternalErrorException;
import se.signatureservice.configuration.common.fields.Fields;
import se.signatureservice.configuration.common.utils.ConfigUtils;
import se.signatureservice.messages.metadata.ReducedMetadata;
import se.signatureservice.messages.metadata.ReducedMetadataImpl;
import se.signatureservice.support.api.ErrorCode;
import se.signatureservice.support.api.v2.BaseAPIException;
import se.signatureservice.support.system.SupportAPIProfile;
import se.signatureservice.support.utils.SupportLibraryUtils;

import java.util.*;

/**
 * Logic to extract information from metadata to maybe modify a SupportAPIProfile.
 *
 * @author Fredrik
 */
public class MetadataService {
    static Logger msgLog = LoggerFactory.getLogger(MetadataService.class);
    final static String DEFAULT_LANGUAGE = "en";

    MessageSource messageSource;

    public MetadataService(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    /**
     * Applies metadata from the given {@link MetadataSource} to a {@link SupportAPIProfile}.
     * <p>
     * This method may update the profile with:
     * <ul>
     *   <li>Trusted authentication services (including default display names from metadata).</li>
     *   <li>AuthnContextClassRefs, if enabled via {@code fetchAuthnContextClassRefFromMetaData}.</li>
     *   <li>Requested certificate attributes, if enabled via {@code fetchCertAttributesFromMetaData}.</li>
     *   <li>UserId attribute mappings, if no explicit mappings exist in the profile or IDP configuration.</li>
     * </ul>
     *
     * @param authenticationServiceId the entityId of the IdP whose metadata is applied
     * @param serviceName             the AttributeConsumingService name (for parsing requested attributes)
     * @param preferredLang           preferred display language for IdP display names (fallback: "en")
     * @param supportAPIProfile       the profile being modified
     * @param metadataSource          source of metadata, keyed by entityId
     * @throws BaseAPIException       if metadata parsing fails or configuration is invalid
     * @throws InternalErrorException on internal configuration/metadata errors
     */
    public void applyMetadataToProfile(
            String authenticationServiceId,
            String serviceName,
            String preferredLang,
            SupportAPIProfile supportAPIProfile,
            MetadataSource metadataSource) throws BaseAPIException, InternalErrorException {
        try {
            Objects.requireNonNull(supportAPIProfile, "supportAPIProfile must not be null");
            Objects.requireNonNull(metadataSource, "metadataSource must not be null");

            setTrustedAuthenticationServices(supportAPIProfile, authenticationServiceId, metadataSource, preferredLang);
            if (ConfigUtils.parseBoolean(
                    supportAPIProfile.isFetchAuthnContextClassRefFromMetaData(),
                    String.format("Invalid 'fetchAuthnContextClassRefFromMetaData' value in '%s' or common under profileConfig. Please specify a valid Boolean value.",
                            supportAPIProfile.getRelatedProfile()),
                    false,
                    false)
            ) {
                ConfigUtils.parseString(
                        authenticationServiceId,
                        String.format(
                                "Input parameter 'authenticationServiceId' must be provided for profile '%s'. " +
                                        "This parameter is required to locate assurance-certification, AuthnContextClassRef, from metadata when " +
                                        "'fetchAuthnContextClassRefFromMetaData=true'.",
                                supportAPIProfile.getRelatedProfile()),
                        true,
                        null);

                msgLog.debug(
                        "Trying to automatically parse assurance-certification, AuthnContextClassRef, from metadata for profile '{}' using authenticationServiceId '{}'",
                        supportAPIProfile.getRelatedProfile(),
                        authenticationServiceId
                );

                fetchAuthnContextClassRefFromMetaData(authenticationServiceId, supportAPIProfile, metadataSource);
            }

            if (ConfigUtils.parseBoolean(
                    supportAPIProfile.isFetchCertAttributesFromMetaData(),
                    String.format("Invalid 'fetchCertAttributesFromMetaData' value in %s or common under profileConfig. Please specify a valid Boolean value.", supportAPIProfile.getRelatedProfile()),
                    false,
                    false)
            ) {
                ConfigUtils.parseString(
                        serviceName,
                        String.format("Input parameter 'serviceName' must be provided for profile '%s'. " +
                                        "This parameter is required to locate requestedCertAttributes from metadata when " +
                                        "'fetchCertAttributesFromMetaData=true'.",
                                supportAPIProfile.getRelatedProfile()),
                        true,
                        null);

                msgLog.debug(
                        "Trying to automatically parse requestedCertAttributes from metadata for profile '{}' using signServiceId '{}' and serviceName '{}'",
                        supportAPIProfile.getRelatedProfile(),
                        supportAPIProfile.getSignServiceId(),
                        serviceName
                );

                fetchCertAttributesFromMetaData(serviceName, supportAPIProfile, metadataSource);
            }

            setDefaultUserIdAttributeMapping(authenticationServiceId, serviceName, supportAPIProfile, metadataSource);
        } catch (Exception e) {
            throw e;
        }
    }

    /**
     * Initializes or updates trusted authentication services in the given profile.
     * <p>
     * If trusted services are already configured, this method tries to fill in missing
     * {@code defaultDisplayName} values from metadata. If no trusted services are defined,
     * it will attempt to initialize them from the given {@code authenticationServiceId}.
     *
     * @param supportAPIProfile       the profile to modify
     * @param authenticationServiceId entityId of the IdP to resolve metadata for
     * @param metadataSource          source of metadata
     * @param preferredLanguage       preferred language for the display name (fallback to "en")
     * @throws BaseAPIException if metadata is invalid or unavailable
     */
    private void setTrustedAuthenticationServices(
            SupportAPIProfile supportAPIProfile,
            String authenticationServiceId,
            MetadataSource metadataSource,
            String preferredLanguage)
            throws BaseAPIException {
        String lang = Optional.ofNullable(preferredLanguage).map(s -> s.trim().toLowerCase()).orElse(Locale.getDefault().getLanguage());

        if (!lang.matches("[a-zA-Z]{2,8}")) {
            var message = String.format("Invalid language format: %s.", lang);
            msgLog.error(message);
            throw ErrorCode.INVALID_PROFILE.toException(message, messageSource);
        }

        try {
            if (supportAPIProfile.getTrustedAuthenticationServices() != null) {
                for (var entry : supportAPIProfile.getTrustedAuthenticationServices().entrySet()) {
                    var serviceName = entry.getKey();
                    var serviceParameters = entry.getValue();
                    String defaultDisplayName;
                    Object defaultDisplayNameObj = serviceParameters.getOrDefault("defaultDisplayName", null);
                    if (defaultDisplayNameObj instanceof String) {
                        defaultDisplayName = (String) defaultDisplayNameObj;
                        if (!defaultDisplayName.isEmpty()) {
                            var message = String.format("defaultDisplayName '%s' already set for idp '%s' with entityId '%s' in trustedAuthenticationServices configuration",
                                    defaultDisplayName, serviceName, serviceParameters.get("entityId"));
                            msgLog.debug(message);
                            continue;
                        }
                    }

                    try {
                        String entityId = (String) serviceParameters.get("entityId");

                        msgLog.debug("TrustedAuthenticationServices configuration already set. Trying to, if set, set defaultDisplayName from metadata with entityId '{}' to idp '{}'", entityId, serviceName);

                        ReducedMetadata metadata = metadataSource.getMetaData(entityId);
                        defaultDisplayName = metadata.getDisplayName(lang, DEFAULT_LANGUAGE);

                        if (defaultDisplayName != null && !defaultDisplayName.isEmpty()) {
                            boolean added = supportAPIProfile.addDefaultDisplayNameToTrustedAuthenticationService(
                                    serviceName, defaultDisplayName
                            );
                            if (added) {
                                msgLog.debug("Successfully set defaultDisplayName '{}' to idp '{}' with entityId '{}' in trustedAuthenticationServices configuration from metadata", defaultDisplayName, serviceName, entityId);
                            } else {
                                msgLog.warn("Unable to set defaultDisplayName '{}' to idp '{}' with entityId '{}' in trustedAuthenticationServices configuration from metadata", defaultDisplayName, serviceName, entityId);
                            }
                        } else {
                            msgLog.warn("No defaultDisplayName, using language settings: {}, found for idp '{}' with entityId '{}' in trustedAuthenticationServices configuration from metadata", lang, serviceName, entityId);
                        }

                    } catch (Exception e) {
                        String entityId = (String) serviceParameters.get("entityId");
                        msgLog.error("Metadata could not be found or loaded for given entityId '{}'. Check that it is available and contains valid metadata", entityId);
                        throw ErrorCode.INTERNAL_ERROR.toException(
                                String.format("Metadata could not be found or loaded for given entityId '%s'. Check that it is available and contains valid metadata. %s", entityId, e.getMessage()),
                                messageSource
                        );
                    }
                }
            } else if (supportAPIProfile.getTrustedAuthenticationServices() == null || supportAPIProfile.getTrustedAuthenticationServices().isEmpty()) {
                try {
                    msgLog.debug("No trustedAuthenticationServices configuration set. Trying to initialize it from metadata with entityId '{}'", authenticationServiceId);

                    ConfigUtils.parseString(
                            authenticationServiceId,
                            String.format("Input parameter 'authenticationServiceId' must be provided for profile '%s'. " +
                                            "This parameter is required to locate the authentication service in metadata.",
                                    supportAPIProfile.getRelatedProfile()),
                            true,
                            null
                    );

                    ReducedMetadata metadata = metadataSource.getMetaData(authenticationServiceId);
                    String defaultDisplayName = metadata.getDisplayName(lang, DEFAULT_LANGUAGE);

                    if (defaultDisplayName != null && !defaultDisplayName.isBlank()) {
                        Map<String, Map<String, Object>> trustedAuthenticationServicesMap = new HashMap<>();
                        String key = defaultDisplayName.replaceAll("\\s+", "");

                        Map<String, Object> innerMap = new HashMap<>();
                        innerMap.put("entityId", authenticationServiceId);
                        innerMap.put("defaultDisplayName", defaultDisplayName);

                        trustedAuthenticationServicesMap.put(key, innerMap);

                        supportAPIProfile.setTrustedAuthenticationServices(trustedAuthenticationServicesMap);

                        msgLog.debug("Successfully set trustedAuthenticationServices configuration for profile '{}': {}",
                                supportAPIProfile.getRelatedProfile(),
                                trustedAuthenticationServicesMap
                        );
                    } else {
                        msgLog.warn("Failed to set trustedAuthenticationServices configuration from metadata with entityId '{}' since no defaultDisplayName was able to be parsed from it",
                                authenticationServiceId
                        );
                    }

                } catch (Exception e) {
                    msgLog.error("Metadata could not be found or loaded. Check that it is available, contains valid metadata and authenticationServiceId '{}'",
                            authenticationServiceId
                    );
                    throw ErrorCode.INTERNAL_ERROR.toException(
                            String.format(
                                    "Metadata could not be found or loaded. Check that it is available, contains valid metadata and authenticationServiceId '%s'. %s",
                                    authenticationServiceId, e.getMessage()
                            ),
                            messageSource
                    );
                }
            }
        } catch (Exception e) {
            var message = String.format("Error occurred while fetching trusted authentication services. %s", e.getMessage());
            msgLog.error(message);
            throw ErrorCode.INTERNAL_ERROR.toException(message, messageSource);
        }
    }

    /**
     * Fetches and adds supported AuthnContextClassRefs from metadata for a given IdP.
     * <p>
     * Updates the corresponding trusted authentication service entry in the profile
     * with the list of supported AuthnContextClassRefs.
     *
     * @param authenticationServiceId IdP entityId to fetch metadata for
     * @param supportAPIProfile       the profile to update
     * @param metadataSource          source of metadata
     * @throws BaseAPIException if metadata retrieval or parsing fails
     */
    private void fetchAuthnContextClassRefFromMetaData(String authenticationServiceId, SupportAPIProfile supportAPIProfile, MetadataSource metadataSource) throws BaseAPIException {
        try {
            ReducedMetadata metadata = metadataSource.getMetaData(authenticationServiceId);
            if (!(metadata != null && metadata.hasEntityAttributes())) {
                msgLog.warn("No matching JAXBElement found from metadata with entityId '{}'", authenticationServiceId);
                return;
            }

            List<String> supportedAuthnContextClassRefs = metadata.getAuthnContextClassRefs();
            if (supportedAuthnContextClassRefs == null || supportedAuthnContextClassRefs.isEmpty()) {
                msgLog.warn("No supported AuthnContextClassRefs found from metadata with entityId '{}'", authenticationServiceId);
                return;
            }

            if (supportAPIProfile.getTrustedAuthenticationServices() != null) {
                for (Map.Entry<String, Map<String, Object>> entry : supportAPIProfile.getTrustedAuthenticationServices().entrySet()) {
                    String idp = entry.getKey();
                    Map<String, Object> value = entry.getValue();

                    if (value != null && authenticationServiceId.equals(value.get("entityId"))) {
                        boolean added = supportAPIProfile.addTrustedAuthenticationServiceAuthnContextClassRef(idp, supportedAuthnContextClassRefs);

                        if (added) {
                            msgLog.debug("Successfully added authnContextClassRef(s) '{}' to idp '{}'", supportedAuthnContextClassRefs, idp);
                        } else {
                            msgLog.debug("Unable to add authnContextClassRef(s) '{}' to idp '{}'", supportedAuthnContextClassRefs, idp);
                        }
                    }
                }
            }
        } catch (Exception e) {
            var v = String.format(
                    "Failed to automatically parse assurance-certification, AuthnContextClassRef, from metadata for profile '%s' using authenticationServiceId '%s'. %s",
                    supportAPIProfile.getRelatedProfile(),
                    authenticationServiceId,
                    e.getMessage()
            );
            msgLog.error(v);
            throw ErrorCode.INTERNAL_ERROR.toException(v, messageSource);
        }
    }

    /**
     * Parses and applies requested certificate attributes from SignService metadata.
     * <p>
     * This method looks up {@code AttributeConsumingServices} by {@code serviceName} and
     * populates {@code requestedCertAttributes} in the profile. Attributes can be mapped:
     * <ul>
     *   <li>Explicitly via {@code metadataCustomCertAttribute} configuration, or</li>
     *   <li>Implicitly via default SAML → cert attribute mappings in {@link Fields}.</li>
     * </ul>
     *
     * @param serviceName       the AttributeConsumingService name
     * @param supportAPIProfile the profile being updated
     * @param metadataSource    source of metadata
     * @throws BaseAPIException if attributes cannot be resolved or mapping conflicts occur
     */
    private void fetchCertAttributesFromMetaData(String serviceName, SupportAPIProfile supportAPIProfile, MetadataSource metadataSource) throws BaseAPIException {
        boolean requestedCertAttributesInitialized = false;

        try {
            ReducedMetadata metadata = metadataSource.getMetaData(supportAPIProfile.getSignServiceId());
            if (metadata != null) {
                List<?> acsList = metadata.getAttributeConsumingServices(serviceName);

                for (Object acsObj : acsList) {
                    ReducedMetadataImpl.AttributeConsumingService attributeConsumingService = (ReducedMetadataImpl.AttributeConsumingService) acsObj;

                    List<?> requestedAttributes = attributeConsumingService.getRequestedAttributes();
                    if (requestedAttributes != null) {
                        for (Object raObj : requestedAttributes) {
                            ReducedMetadataImpl.RequestedAttribute requestedAttribute = (ReducedMetadataImpl.RequestedAttribute) raObj;

                            Map<String, Object> requestedAttributeMap = new LinkedHashMap<>();
                            StringBuilder friendlyName = new StringBuilder();

                            if (supportAPIProfile.getMetadataCustomCertAttribute() != null) {
                                setReqCertAttrFromMetaDataCustomCertAttr(
                                        supportAPIProfile, friendlyName, requestedAttributeMap, requestedAttribute
                                );
                            }

                            if (requestedAttributeMap.isEmpty()) {
                                String name = requestedAttribute.getName() != null ? requestedAttribute.getName().trim() : null;

                                boolean match = Fields.tokenFieldMapToDefaultSAMLAttributes.entrySet()
                                        .stream()
                                        .anyMatch(entry -> ((List<?>) entry.getValue()).contains(name));

                                if (match) {
                                    setReqCertAttrFromMetaData(friendlyName, requestedAttributeMap, requestedAttribute);
                                }
                            }

                            if (requestedAttributeMap.isEmpty()) {
                                var v = String.format(
                                        "No matching attribute found for RequestedAttribute with Name '%s'. Please ensure that a corresponding attribute is correctly configured in metadataCustomCertAttribute",
                                        requestedAttribute.getName()
                                );
                                msgLog.error(v);
                                throw ErrorCode.INTERNAL_ERROR.toException(v);
                            }

                            String friendlyNameStr = friendlyName.toString();
                            if (!friendlyNameStr.isBlank()) {
                                if (!requestedCertAttributesInitialized) {
                                    supportAPIProfile.setRequestedCertAttributes(new LinkedHashMap<>());
                                    requestedCertAttributesInitialized = true;
                                }

                                boolean alreadyMapped = supportAPIProfile.getRequestedCertAttributes()
                                        .keySet()
                                        .stream()
                                        .anyMatch(key -> key.equalsIgnoreCase(friendlyNameStr));

                                if (alreadyMapped) {
                                    msgLog.error(
                                            "Unable to parse requestedCertAttribute with friendlyName '{}' and samlAttributeName '{}' because it's already mapped.",
                                            friendlyNameStr,
                                            requestedAttributeMap.get("samlAttributeName")
                                    );
                                    throw ErrorCode.INVALID_PROFILE.toException(String.format(
                                            "Unable to parse requestedCertAttribute with friendlyName '%s' and samlAttributeName '%s' because it's already mapped.",
                                            friendlyNameStr,
                                            requestedAttributeMap.get("samlAttributeName")
                                    ));
                                }

                                supportAPIProfile.addRequestedCertAttribute(friendlyNameStr, requestedAttributeMap);

                                msgLog.debug(
                                        "RequestedCertAttribute with friendlyName '{}' successfully parsed from metadata using ServiceId '{}' and serviceName '{}'. Resulting attribute map: {}",
                                        friendlyNameStr,
                                        supportAPIProfile.getSignServiceId(),
                                        serviceName,
                                        requestedAttributeMap
                                );
                            } else {
                                msgLog.error("Unexpected Error, No 'friendlyName' could be parsed.");
                                throw ErrorCode.INTERNAL_ERROR.toException("Unexpected Error, No 'friendlyName' could be parsed.");
                            }
                        }
                    }
                    break; // exit after the first matching attributeConsumingService
                }
            }
        } catch (Exception e) {
            var v = String.format(
                    "Failed to automatically parse requestedCertAttributes from metadata for profile '%s' with signServiceId '%s' and serviceName '%s'. %s",
                    supportAPIProfile.getRelatedProfile(),
                    supportAPIProfile.getSignServiceId(),
                    serviceName,
                    e.getMessage()
            );
            msgLog.error(v);
            throw ErrorCode.INTERNAL_ERROR.toException(v, messageSource);
        }

        if (!requestedCertAttributesInitialized) {
            msgLog.warn(
                    "No RequestedAttribute was found in metadata for profile '{}' with signServiceId '{}' and serviceName '{}'. Consequently, 'requestedCertAttributes' will remain unchanged as, if, configured.",
                    supportAPIProfile.getRelatedProfile(),
                    supportAPIProfile.getSignServiceId(),
                    serviceName
            );
        }
    }

    /**
     * Ensures that the profile has a default UserIdAttributeMapping.
     * <p>
     * If not already configured in the profile or IdP-specific configuration,
     * this method attempts to derive a default mapping from metadata by
     * matching requested attributes against {@code defaultUserIdAttributeMappingValues}.
     *
     * @param authenticationServiceId the IdP entityId
     * @param serviceName             the AttributeConsumingService name
     * @param supportAPIProfile       the profile to update
     * @param metadataSource          source of metadata
     * @throws BaseAPIException if no valid mapping can be determined or multiple matches are found
     */
    void setDefaultUserIdAttributeMapping(String authenticationServiceId, String serviceName, SupportAPIProfile supportAPIProfile, MetadataSource metadataSource) throws BaseAPIException {
        try {
            Map<String, String> userIdAttributeMappings = SupportLibraryUtils.getUserIdAttributeMappings(supportAPIProfile);
            Map<String, Map<String, Object>> authConfUserIdAttributeMappings =
                    SupportLibraryUtils.findAuthConfUserIdAttributeMappings(authenticationServiceId, supportAPIProfile);

            if (!userIdAttributeMappings.isEmpty()) {
                if (userIdAttributeMappings.containsKey("userIdAttributeMapping")) {
                    msgLog.debug(
                            "userIdAttributeMapping '{}' is set fetched from profile-configuration 'userIdAttributeMapping' setting",
                            userIdAttributeMappings.get("userIdAttributeMapping")
                    );
                }
                if (userIdAttributeMappings.containsKey("defaultUserIdAttributeMapping")) {
                    msgLog.debug(
                            "defaultUserIdAttributeMapping '{}' is set fetched from profile-configuration 'defaultUserIdAttributeMapping' setting",
                            userIdAttributeMappings.get("defaultUserIdAttributeMapping")
                    );
                }
            }

            if (authConfUserIdAttributeMappings != null && !authConfUserIdAttributeMappings.isEmpty()) {
                msgLog.debug(
                        "userIdAttributeMapping is set fetched from authentication service configuration in idp(s): {}.",
                        authConfUserIdAttributeMappings.keySet()
                );
            }

            boolean noMappingsDefined = (userIdAttributeMappings.isEmpty())
                    && (authConfUserIdAttributeMappings == null || authConfUserIdAttributeMappings.isEmpty());

            if (noMappingsDefined) {
                msgLog.debug(
                        "No userIdAttributeMapping or defaultUserIdAttributeMapping could be found in profile '{}' or IDP authentication service configuration. Attempting to fetch from Metadata using signServiceId '{}'",
                        supportAPIProfile.getRelatedProfile(),
                        supportAPIProfile.getSignServiceId()
                );

                ReducedMetadata metadata = metadataSource.getMetaData(supportAPIProfile.getSignServiceId());

                if (metadata != null) {
                    ConfigUtils.parseString(
                            serviceName,
                            String.format("Input parameter 'serviceName' must be provided for profile '%s'. " +
                                            "This parameter is required to locate UserIdAttributeMapping from metadata.",
                                    supportAPIProfile.getRelatedProfile()),
                            true,
                            null);

                    List<?> acsList = metadata.getAttributeConsumingServices(serviceName);

                    for (Object acsObj : acsList) {
                        ReducedMetadataImpl.AttributeConsumingService attributeConsumingService = (ReducedMetadataImpl.AttributeConsumingService) acsObj;

                        List<String> requestedAttributeNames = new ArrayList<>();
                        if (attributeConsumingService.getRequestedAttributes() != null) {
                            for (Object raObj : attributeConsumingService.getRequestedAttributes()) {
                                ReducedMetadataImpl.RequestedAttribute ra = (ReducedMetadataImpl.RequestedAttribute) raObj;
                                if (ra.getName() != null) {
                                    requestedAttributeNames.add(ra.getName());
                                }
                            }
                        }

                        List<String> matchesFound = DefaultUserIdAttributeMappingValues.findMatches(
                                requestedAttributeNames,
                                supportAPIProfile.getDefaultUserIdAttributeMappingValues()
                        );

                        if (matchesFound.size() == 1) {
                            msgLog.debug(
                                    "Single DefaultUserIdAttributeMapping match found in metadata: '{}' for authenticationServiceId '{}', ServiceId '{}' and serviceName '{}'",
                                    matchesFound.get(0),
                                    authenticationServiceId != null ? authenticationServiceId : "<not provided>",
                                    supportAPIProfile.getSignServiceId(),
                                    serviceName
                            );
                            supportAPIProfile.setDefaultUserIdAttributeMapping(matchesFound.get(0));
                        } else if (matchesFound.size() > 1) {
                            var v = String.format(
                                    "Multiple DefaultUserIdAttributeMapping matches found in metadata: '%s', but no default DefaultUserIdAttributeMapping is set in profile configuration",
                                    matchesFound
                            );
                            msgLog.error(v);
                            throw ErrorCode.INTERNAL_ERROR.toException(v, messageSource);
                        } else {
                            msgLog.error("No DefaultUserIdAttributeMapping matches found in metadata nor in default DefaultUserIdAttributeMapping profile configuration");
                            throw ErrorCode.INTERNAL_ERROR.toException(
                                    "No DefaultUserIdAttributeMapping matches found in metadata nor in default DefaultUserIdAttributeMapping profile configuration",
                                    messageSource
                            );
                        }
                    }
                }
            }
        } catch (Exception e) {
            var v = String.format(
                    "Failed to automatically parse DefaultUserIdAttributeMapping from metadata for profile '%s' with authenticationServiceId '%s', ServiceId '%s' and serviceName '%s'. %s",
                    supportAPIProfile.getRelatedProfile(),
                    authenticationServiceId,
                    supportAPIProfile.getSignServiceId(),
                    serviceName,
                    e.getMessage()
            );
            msgLog.error(v);
            throw ErrorCode.INTERNAL_ERROR.toException(v, messageSource);
        }
    }

    /**
     * Maps a RequestedAttribute from metadata using the profile’s
     * {@code metadataCustomCertAttribute} configuration.
     * <p>
     * Matches are based on {@code samlAttributeName}. On a match, this method
     * populates {@code requestedAttributeMap} with:
     * <ul>
     *   <li>{@code samlAttributeName}</li>
     *   <li>{@code certAttributeRef}</li>
     *   <li>{@code certNameType} (if defined or inferred)</li>
     *   <li>{@code required}</li>
     * </ul>
     * and sets the {@code friendlyName}.
     *
     * @throws BaseAPIException if configuration is invalid or no friendlyName can be determined
     */
    private void setReqCertAttrFromMetaDataCustomCertAttr(
            SupportAPIProfile supportAPIProfile,
            StringBuilder friendlyName,
            Map<String, Object> requestedAttributeMap,
            ReducedMetadataImpl.RequestedAttribute requestedAttribute
    ) throws BaseAPIException {
        try {
            Map<String, Map<String, Object>> metadataCustomCertAttributeMap = supportAPIProfile.getMetadataCustomCertAttribute();
            if (metadataCustomCertAttributeMap != null) {
                for (Map.Entry<String, Map<String, Object>> entry : metadataCustomCertAttributeMap.entrySet()) {
                    String key = entry.getKey();
                    Map<String, Object> value = entry.getValue();

                    Object samlAttributeNameObj = value != null ? value.get("samlAttributeName") : null;

                    List<String> samlAttributeNames = new ArrayList<>();
                    if (samlAttributeNameObj instanceof String) {
                        String parsed = ConfigUtils.parseString(
                                samlAttributeNameObj,
                                String.format("Invalid or empty value set in %s.metadataCustomCertAttribute.%s.samlAttributeName: %s. Please specify a valid String value.",
                                        supportAPIProfile.getRelatedProfile(), key, samlAttributeNameObj),
                                true,
                                null
                        );
                        samlAttributeNames.add(parsed);
                    } else if (samlAttributeNameObj instanceof List<?>) {
                        List<String> rawList = (List<String>) samlAttributeNameObj;
                        List<String> strings = ConfigUtils.parseListOfString(
                                rawList,
                                String.format("Invalid or empty value in the list for %s.metadataCustomCertAttribute.%s.samlAttributeName: %s. Please specify valid String value(s).",
                                        supportAPIProfile.getRelatedProfile(), key, rawList),
                                true
                        );
                        if (strings != null) {
                            samlAttributeNames.addAll(strings);
                        }
                    } else {
                        throw ErrorCode.INVALID_CONFIGURATION.toException(
                                String.format("Invalid value for 'samlAttributeName' under %s.metadataCustomCertAttribute.%s. It must be either a single string or a list of strings.",
                                        supportAPIProfile.getRelatedProfile(), key),
                                messageSource
                        );
                    }

                    for (String matchedSamlAttribute : samlAttributeNames) {
                        if (requestedAttribute != null && matchedSamlAttribute.equals(requestedAttribute.getName())) {
                            String certAttributeRef = ConfigUtils.parseString(
                                    value.get("certAttributeRef"),
                                    String.format("Invalid or missing 'certAttributeRef' value in: %s.metadataCustomCertAttribute.%s. Please specify a valid String value.",
                                            supportAPIProfile.getRelatedProfile(), key),
                                    true,
                                    null
                            );

                            String certNameType = ConfigUtils.parseString(
                                    value.get("certNameType"),
                                    String.format("Invalid or missing 'certNameType' value in %s.metadataCustomCertAttribute.%s. Please specify a valid String value.",
                                            supportAPIProfile.getRelatedProfile(), key),
                                    false,
                                    null
                            );

                            Boolean required = ConfigUtils.parseBoolean(
                                    value.get("required"),
                                    String.format("Invalid or missing 'required' value in %s.metadataCustomCertAttribute.%s. Please specify a valid Boolean value.",
                                            supportAPIProfile.getRelatedProfile(), key),
                                    false,
                                    requestedAttribute.isRequired()
                            );

                            if (requestedAttribute.isRequired() != null) {
                                requestedAttributeMap.put("required", requestedAttribute.isRequired());
                                msgLog.debug("required set to: {}", requestedAttributeMap.get("required"));
                            }

                            requestedAttributeMap.put("samlAttributeName", matchedSamlAttribute);
                            requestedAttributeMap.put("certAttributeRef", certAttributeRef);
                            msgLog.debug("RequestedAttribute added with samlAttributeName '{}' and certAttributeRef '{}' for metadataCustomCertAttribute with friendlyName '{}' under profile '{}'",
                                    matchedSamlAttribute, certAttributeRef, key, supportAPIProfile.getRelatedProfile());

                            if (certNameType != null && !certNameType.isBlank()) {
                                requestedAttributeMap.put("certNameType", certNameType);
                            } else {
                                String lowerKey = key.toLowerCase();
                                certNameType = Fields.fieldNameToAttrType.get(lowerKey);

                                if (certNameType == null) {
                                    String refKey = Fields.fieldNameToAttrRef.entrySet().stream()
                                            .filter(e -> certAttributeRef.equals(e.getValue()))
                                            .map(Map.Entry::getKey)
                                            .findFirst()
                                            .orElse(null);
                                    if (refKey != null) {
                                        certNameType = Fields.fieldNameToAttrType.get(refKey);
                                    }
                                }

                                if (certNameType != null) {
                                    requestedAttributeMap.put("certNameType", ConfigUtils.parseString(
                                            certNameType,
                                            "Unable to set certNameType from metadata via metadataCustomCertAttribute",
                                            false,
                                            null
                                    ));
                                }
                            }

                            if (required != null) {
                                requestedAttributeMap.put("required", required);
                            }

                            friendlyName.setLength(0);
                            try {
                                String parsedFriendlyName = ConfigUtils.parseString(
                                        key,
                                        String.format("Empty or invalid value for friendlyName key in %s.metadataCustomCertAttribute: %s. Please specify a valid String value.",
                                                supportAPIProfile.getRelatedProfile(), key),
                                        true,
                                        null
                                );
                                friendlyName.append(parsedFriendlyName != null ? parsedFriendlyName.trim() : "");
                            } catch (Exception e1) {
                                try {
                                    String fallbackKey = Fields.fieldNameToAttrRef.entrySet().stream()
                                            .filter(e -> certAttributeRef.equals(e.getValue()))
                                            .map(Map.Entry::getKey)
                                            .findFirst()
                                            .orElse(null);

                                    String fallbackFriendlyName = ConfigUtils.parseString(
                                            fallbackKey,
                                            String.format("No friendlyName match found for %s.metadataCustomCertAttribute.%s.certAttributeRef: %s.",
                                                    supportAPIProfile.getRelatedProfile(), key, certAttributeRef),
                                            true,
                                            null
                                    );
                                    friendlyName.append(fallbackFriendlyName != null ? fallbackFriendlyName.trim() : "");
                                } catch (Exception e2) {
                                    throw new Exception("Unable to append friendlyName. " + e1.getMessage() + " " + e2.getMessage());
                                }
                            }

                            // Stop iterating after match is found
                            return;
                        }
                    }
                }
            }
        } catch (Exception e) {
            var v = String.format(
                    "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. %s",
                    e.getMessage()
            );
            msgLog.error(v);
            throw ErrorCode.INTERNAL_ERROR.toException(v, messageSource);
        }
    }

    /**
     * Maps a RequestedAttribute from metadata using built-in defaults
     * (without {@code metadataCustomCertAttribute} overrides).
     * <p>
     * Friendly name, SAML attribute name, certificate attribute reference,
     * and certificate name type are derived from {@link Fields}.
     *
     * @param friendlyName          StringBuilder that will be updated with the resolved friendly name
     * @param requestedAttributeMap map to populate with attribute metadata
     * @param requestedAttribute    the attribute parsed from metadata
     * @throws BaseAPIException if attribute parsing fails
     */
    private void setReqCertAttrFromMetaData(StringBuilder friendlyName, Map<String, Object> requestedAttributeMap, ReducedMetadataImpl.RequestedAttribute requestedAttribute) throws BaseAPIException {
        try {
            friendlyName.setLength(0);
            String determinedFriendlyName = determineFriendlyName(requestedAttribute);

            if (determinedFriendlyName != null && !determinedFriendlyName.isBlank()) {
                friendlyName.append(determinedFriendlyName);

                String samlAttributeName = ConfigUtils.parseString(
                        requestedAttribute != null ? requestedAttribute.getName() : null,
                        "Unable to set samlAttributeName from metadata",
                        true,
                        null
                );
                String certAttributeRef = ConfigUtils.parseString(
                        Fields.fieldNameToAttrRef.get(determinedFriendlyName.toLowerCase()),
                        String.format("Unable to set certAttributeRef from metadata via parsed friendlyname '%s'", determinedFriendlyName),
                        true,
                        null
                );
                String certNameType = ConfigUtils.parseString(
                        Fields.fieldNameToAttrType.get(determinedFriendlyName.toLowerCase()),
                        String.format("Unable to set certNameType from metadata via parsed friendlyname '%s'", determinedFriendlyName),
                        true,
                        null
                );

                requestedAttributeMap.put("samlAttributeName", samlAttributeName);
                requestedAttributeMap.put("certAttributeRef", certAttributeRef);
                requestedAttributeMap.put("certNameType", certNameType);

                if (requestedAttribute != null && requestedAttribute.isRequired() != null) {
                    requestedAttributeMap.put("required", requestedAttribute.isRequired());
                    msgLog.debug("required set to: {}", requestedAttributeMap.get("required"));
                }

                msgLog.debug("RequestedAttribute added with samlAttributeName '{}', certAttributeRef '{}' and certNameType '{}' for friendlyName '{}'",
                        samlAttributeName,
                        certAttributeRef,
                        certNameType,
                        friendlyName
                );
            }
        } catch (Exception e) {
            msgLog.error("Failed to automatically parse requestedCertAttributes from Metadata. {}", e.getMessage());
            throw ErrorCode.INTERNAL_ERROR.toException(
                    String.format("Failed to automatically parse requestedCertAttributes from Metadata. %s", e.getMessage()),
                    messageSource
            );
        }
    }

    /**
     * Determines a friendlyName for a requested attribute.
     * <p>
     * The logic:
     * <ul>
     *   <li>Use the provided {@code requestedAttribute.friendlyName} if valid.</li>
     *   <li>Otherwise, attempt to map {@code requestedAttribute.name} via default SAML-to-token mappings in {@link Fields}.</li>
     * </ul>
     * Returns {@code null} if no friendly name can be determined.
     *
     * @param requestedAttributeType the attribute from metadata
     * @return the resolved friendlyName, or null if none found
     */
    static String determineFriendlyName(ReducedMetadataImpl.RequestedAttribute requestedAttributeType) {
        String friendlyName = requestedAttributeType != null && requestedAttributeType.getFriendlyName() != null
                ? requestedAttributeType.getFriendlyName().trim()
                : null;

        if (friendlyName != null && !friendlyName.isBlank() && Fields.fieldNameToAttrRef.containsKey(friendlyName.toLowerCase())) {
            msgLog.debug("FriendlyName set from requestedAttributeType.friendlyName to: '{}'", friendlyName.trim());
            return friendlyName;
        }

        String tokenFriendlyName = null;
        for (Map.Entry<String, List<String>> entry : Fields.tokenFieldMapToDefaultSAMLAttributes.entrySet()) {
            List<String> values = entry.getValue();
            if (values != null && requestedAttributeType != null && requestedAttributeType.getName() != null &&
                    values.contains(requestedAttributeType.getName())) {
                tokenFriendlyName = entry.getKey();
                break;
            }
        }

        if (tokenFriendlyName != null) {
            msgLog.debug("FriendlyName set from requestedAttributeType.name to '{}'", tokenFriendlyName);
            return tokenFriendlyName;
        }

        msgLog.debug("Unable to set any friendlyName from metadata for requestedAttribute with name '{}'",
                requestedAttributeType != null ? requestedAttributeType.getName() : null);
        return null;
    }
}
