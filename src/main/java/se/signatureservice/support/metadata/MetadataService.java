package se.signatureservice.support.metadata;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import se.signatureservice.configuration.common.InternalErrorException;
import se.signatureservice.configuration.common.fields.Fields;
import se.signatureservice.configuration.common.utils.ConfigUtils;
import se.signatureservice.messages.metadata.ReducedMetadata;
import se.signatureservice.messages.metadata.ReducedMetadataImpl;
import se.signatureservice.support.api.v2.BaseAPIException;
import se.signatureservice.support.api.ErrorCode;
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
     * Populate Idp displayNames from metadata, and conditionally fetch AuthnContextClassRefs, CertAttributes and UserIdAttributeMapping, from metadata
     * @param authenticationServiceId, The entity whose metadata will be applied
     * @param serviceName, To match attributeConsumingServices in the metadata
     * @param preferredLang, For getting displayName
     * @param supportAPIProfile, The profile to modify
     */
    public void applyMetadataToProfile(
            String authenticationServiceId,
            String serviceName,
            String preferredLang,
            SupportAPIProfile supportAPIProfile,
            MetadataSource metadataSource) throws BaseAPIException, InternalErrorException {
        try {
            setTrustedAuthenticationServices(supportAPIProfile, authenticationServiceId, metadataSource, preferredLang);
            if (ConfigUtils.parseBoolean(
                    supportAPIProfile.isFetchAuthnContextClassRefFromMetaData(),
                    String.format("Invalid 'fetchAuthnContextClassRefFromMetaData' value in '%s' or common under profileConfig. Please specify a valid Boolean value.",
                            supportAPIProfile.getRelatedProfile()),
                    false, false)) {

                msgLog.info(String.format(
                        "Trying to automatically parse assurance-certification, AuthnContextClassRef, from metadata for profile '%s' using authenticationServiceId '%s'",
                        supportAPIProfile.getRelatedProfile(), authenticationServiceId
                ));

                fetchAuthnContextClassRefFromMetaData(authenticationServiceId, supportAPIProfile, metadataSource);
            }

            if (ConfigUtils.parseBoolean(
                    supportAPIProfile.isFetchCertAttributesFromMetaData(),
                    String.format("Invalid 'fetchCertAttributesFromMetaData' value in %s or common under profileConfig. Please specify a valid Boolean value.",
                            supportAPIProfile.getRelatedProfile()),
                    false, false)) {

                msgLog.info(String.format(
                        "Trying to automatically parse requestedCertAttributes from metadata for profile '%s' using signServiceId '%s' and serviceName '%s'",
                        supportAPIProfile.getRelatedProfile(),
                        supportAPIProfile.getSignServiceId(),
                        serviceName
                ));

                fetchCertAttributesFromMetaData(serviceName, supportAPIProfile, metadataSource);
            }

            setDefaultUserIdAttributeMapping(authenticationServiceId, serviceName, supportAPIProfile, metadataSource);
        } catch (Exception e) {
            throw e;
        }
    }

    /**
     * Set Authentication Services to given list for given Entity Descriptors.
     *
     * @param supportAPIProfile Support service API profile configuration
     * @param authenticationServiceId identity provider to use during signature process
     * @param idpEntities list of Entity Descriptors.
     * @param lang Preferred language of display name to primarily be selected.
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
            if(supportAPIProfile.getTrustedAuthenticationServices() != null) {
                for (var entry : supportAPIProfile.getTrustedAuthenticationServices().entrySet()) {
                    var serviceName = entry.getKey();
                    var serviceParameters = entry.getValue();
                    String defaultDisplayName;
                    Object defaultDisplayNameObj = serviceParameters.getOrDefault("defaultDisplayName", null);
                    if(defaultDisplayNameObj instanceof String) {
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

                        msgLog.debug(String.format(
                                "TrustedAuthenticationServices configuration already set. Trying to, if set, set defaultDisplayName from metadata with entityId '%s' to idp '%s'",
                                entityId, serviceName
                        ));

                        ReducedMetadata metadata = metadataSource.getMetaData(entityId);
                        defaultDisplayName = metadata.getDisplayName(lang, DEFAULT_LANGUAGE);

                        if (defaultDisplayName != null && !defaultDisplayName.isEmpty()) {
                            boolean added = supportAPIProfile.addDefaultDisplayNameToTrustedAuthenticationService(
                                    serviceName, defaultDisplayName
                            );
                            if (added) {
                                msgLog.info(String.format(
                                        "Successfully set defaultDisplayName '%s' to idp '%s' with entityId '%s' in trustedAuthenticationServices configuration from metadata",
                                        defaultDisplayName, serviceName, entityId
                                ));
                            } else {
                                msgLog.warn(String.format(
                                        "Unable to set defaultDisplayName '%s' to idp '%s' with entityId '%s' in trustedAuthenticationServices configuration from metadata",
                                        defaultDisplayName, serviceName, entityId
                                ));
                            }
                        } else {
                            msgLog.warn(String.format(
                                    "No defaultDisplayName, using language settings: %s, found for idp '%s' with entityId '%s' in trustedAuthenticationServices configuration from metadata",
                                    lang, serviceName, entityId
                            ));
                        }

                    } catch (Exception e) {
                        String entityId = (String) serviceParameters.get("entityId");
                        msgLog.error(String.format(
                                "Metadata could not be found or loaded for given entityId '%s'. Check that it is available and contains valid metadata",
                                entityId
                        ));
                        throw ErrorCode.INTERNAL_ERROR.toException(
                                String.format("Metadata could not be found or loaded for given entityId '%s'. Check that it is available and contains valid metadata. %s", entityId, e.getMessage()),
                                messageSource
                        );
                    }
                }
            }

            if (supportAPIProfile.getTrustedAuthenticationServices() == null || supportAPIProfile.getTrustedAuthenticationServices().isEmpty()) {
                try {
                    msgLog.debug(String.format(
                            "No trustedAuthenticationServices configuration set. Trying to initialize it from metadata with entityId '%s'",
                            authenticationServiceId
                    ));

                    ReducedMetadata metadata = metadataSource.getMetaData(authenticationServiceId);
                    String defaultDisplayName = metadata.getDisplayName(lang, DEFAULT_LANGUAGE);

                    if (defaultDisplayName != null && !defaultDisplayName.isBlank()) {
                        Map<String, Map<String, Object>> trustedAuthenticationServicesMap = new HashMap<>();
                        String key = defaultDisplayName.replaceAll("\\s+", "");

                        Map<String, Object> innerMap = new HashMap<>();
                        innerMap.put("entityId", authenticationServiceId);
                        innerMap.put("defaultDisplayName", defaultDisplayName);

                        trustedAuthenticationServicesMap.put(key, innerMap);

                        if (supportAPIProfile != null) {
                            supportAPIProfile.setTrustedAuthenticationServices(trustedAuthenticationServicesMap);
                        }

                        msgLog.info(String.format(
                                "Successfully set trustedAuthenticationServices configuration for profile '%s': %s",
                                supportAPIProfile != null ? supportAPIProfile.getRelatedProfile() : "null",
                                trustedAuthenticationServicesMap
                        ));
                    } else {
                        msgLog.warn(String.format(
                                "Failed to set trustedAuthenticationServices configuration from metadata with entityId '%s' since no defaultDisplayName was able to be parsed from it",
                                authenticationServiceId
                        ));
                    }

                } catch (Exception e) {
                    msgLog.error(String.format(
                            "Metadata could not be found or loaded. Check that it is available, contains valid metadata and authenticationServiceId '%s'",
                            authenticationServiceId
                    ));
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
     * Fetch and set AuthnContextClassRef from metadata.
     * @param authenticationServiceId identity provider to use during signature process
     * @param serviceName
     * @param supportAPIProfile Support service API profile configuration
     */
    private void fetchAuthnContextClassRefFromMetaData(String authenticationServiceId, SupportAPIProfile supportAPIProfile, MetadataSource metadataSource) throws BaseAPIException {
        try {
            ReducedMetadata metadata = metadataSource.getMetaData(authenticationServiceId);
            boolean hasElements = metadata != null && metadata.hasEntityAttributes();
            if (!hasElements) {
                msgLog.warn(String.format(
                        "No matching JAXBElement found from metadata with entityId '%s'",
                        authenticationServiceId
                ));
                return;
            }

            List<String> supportedAuthnContextClassRefs = metadata.getAuthnContextClassRefs();
            if (supportedAuthnContextClassRefs == null || supportedAuthnContextClassRefs.isEmpty()) {
                msgLog.warn(String.format(
                        "No supported AuthnContextClassRefs found from metadata with entityId '%s'",
                        authenticationServiceId
                ));
                return;
            }

            if (supportAPIProfile != null && supportAPIProfile.getTrustedAuthenticationServices() != null) {
                for (Map.Entry<String, Map<String, Object>> entry : supportAPIProfile.getTrustedAuthenticationServices().entrySet()) {
                    String idp = entry.getKey();
                    Map<String, Object> value = entry.getValue();

                    if (value != null && authenticationServiceId.equals(value.get("entityId"))) {
                        boolean added = supportAPIProfile.addTrustedAuthenticationServiceAuthnContextClassRef(idp, supportedAuthnContextClassRefs);

                        if (added) {
                            msgLog.info(String.format(
                                    "Successfully added authnContextClassRef(s) '%s' to idp '%s'",
                                    supportedAuthnContextClassRefs, idp
                            ));
                        } else {
                            msgLog.debug(String.format(
                                    "Unable to add authnContextClassRef(s) '%s' to idp '%s'",
                                    supportedAuthnContextClassRefs, idp
                            ));
                        }
                    }
                }
            }
        } catch (Exception e) {
            var v = String.format(
                    "Failed to automatically parse assurance-certification, AuthnContextClassRef, from metadata for profile '%s' using authenticationServiceId '%s'. %s",
                    supportAPIProfile != null ? supportAPIProfile.getRelatedProfile() : "null",
                    authenticationServiceId,
                    e.getMessage()
            );
            msgLog.error(v);
            throw ErrorCode.INTERNAL_ERROR.toException(
                    v, messageSource
            );
        }
    }

    /**
     * Fetch and set requestedCertAttributes from metadata.
     * @param serviceName
     * @param supportAPIProfile Support service API profile configuration
     */
    private void fetchCertAttributesFromMetaData(String serviceName, SupportAPIProfile supportAPIProfile, MetadataSource metadataSource) throws BaseAPIException {
        boolean requestedCertAttributesInitialized = false;

        try {
            ReducedMetadata metadata = metadataSource != null
                    ? metadataSource.getMetaData(supportAPIProfile.getSignServiceId())
                    : null;

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
                                    supportAPIProfile.setRequestedCertAttributes(new HashMap<>());
                                    requestedCertAttributesInitialized = true;
                                }

                                boolean alreadyMapped = supportAPIProfile.getRequestedCertAttributes()
                                        .keySet()
                                        .stream()
                                        .anyMatch(key -> key.equalsIgnoreCase(friendlyNameStr));

                                if (alreadyMapped) {
                                    msgLog.error(String.format(
                                            "Unable to parse requestedCertAttribute with friendlyName '%s' and samlAttributeName '%s' because it's already mapped.",
                                            friendlyNameStr,
                                            requestedAttributeMap.get("samlAttributeName")
                                    ));
                                    throw ErrorCode.INVALID_PROFILE.toException(String.format(
                                            "Unable to parse requestedCertAttribute with friendlyName '%s' and samlAttributeName '%s' because it's already mapped.",
                                            friendlyNameStr,
                                            requestedAttributeMap.get("samlAttributeName")
                                    ));
                                }

                                supportAPIProfile.addRequestedCertAttribute(friendlyNameStr, requestedAttributeMap);

                                msgLog.info(String.format(
                                        "RequestedCertAttribute with friendlyName '%s' successfully parsed from metadata using ServiceId '%s' and serviceName '%s'. Resulting attribute map: %s",
                                        friendlyNameStr,
                                        supportAPIProfile.getSignServiceId(),
                                        serviceName,
                                        requestedAttributeMap
                                ));
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
                    supportAPIProfile != null ? supportAPIProfile.getRelatedProfile() : "null",
                    supportAPIProfile != null ? supportAPIProfile.getSignServiceId() : "null",
                    serviceName,
                    e.getMessage()
            );
            msgLog.error(v);

            throw ErrorCode.INTERNAL_ERROR.toException(v, messageSource);
        }

        if (!requestedCertAttributesInitialized) {
            msgLog.warn(String.format(
                    "No RequestedAttribute was found in metadata for profile '%s' with signServiceId '%s' and serviceName '%s'. Consequently, 'requestedCertAttributes' will remain unchanged as, if, configured.",
                    supportAPIProfile.getRelatedProfile(),
                    supportAPIProfile.getSignServiceId(),
                    serviceName
            ));
        }
    }

    /**
     * Set DefaultUserIdAttributeMapping from metadata.
     * @param authenticationServiceId identity provider to use during signature process
     * @param serviceName
     * @param supportAPIProfile Support service API profile configuration
     */
    void setDefaultUserIdAttributeMapping(String authenticationServiceId, String serviceName, SupportAPIProfile supportAPIProfile, MetadataSource metadataSource) throws BaseAPIException {
        try {
            Map<String, String> userIdAttributeMappings = SupportLibraryUtils.getUserIdAttributeMappings(supportAPIProfile);
            Map<String, Map<String, Object>> authConfUserIdAttributeMappings =
                    SupportLibraryUtils.findAuthConfUserIdAttributeMappings(authenticationServiceId, supportAPIProfile);

            if (userIdAttributeMappings != null && !userIdAttributeMappings.isEmpty()) {
                if (userIdAttributeMappings.containsKey("userIdAttributeMapping")) {
                    msgLog.debug(String.format(
                            "userIdAttributeMapping '%s' is set fetched from profile-configuration 'userIdAttributeMapping' setting",
                            userIdAttributeMappings.get("userIdAttributeMapping")
                    ));
                }
                if (userIdAttributeMappings.containsKey("defaultUserIdAttributeMapping")) {
                    msgLog.debug(String.format(
                            "defaultUserIdAttributeMapping '%s' is set fetched from profile-configuration 'defaultUserIdAttributeMapping' setting",
                            userIdAttributeMappings.get("defaultUserIdAttributeMapping")
                    ));
                }
            }

            if (authConfUserIdAttributeMappings != null && !authConfUserIdAttributeMappings.isEmpty()) {
                msgLog.debug(String.format(
                        "userIdAttributeMapping is set fetched from authentication service configuration in idp(s): %s.",
                        authConfUserIdAttributeMappings.keySet()
                ));
            }

            boolean noMappingsDefined = (userIdAttributeMappings == null || userIdAttributeMappings.isEmpty())
                    && (authConfUserIdAttributeMappings == null || authConfUserIdAttributeMappings.isEmpty());

            if (noMappingsDefined) {
                msgLog.debug(String.format(
                        "No userIdAttributeMapping or defaultUserIdAttributeMapping could be found in profile '%s' or IDP authentication service configuration. Attempting to fetch from Metadata using signServiceId '%s'",
                        supportAPIProfile.getRelatedProfile(),
                        supportAPIProfile.getSignServiceId()
                ));

                ReducedMetadata metadata = metadataSource.getMetaData(supportAPIProfile.getSignServiceId());

                if (metadata != null) {
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
                            msgLog.info(String.format(
                                    "Single DefaultUserIdAttributeMapping match found in metadata: '%s' for authenticationServiceId '%s', ServiceId '%s' and serviceName '%s'",
                                    matchesFound.get(0),
                                    authenticationServiceId,
                                    supportAPIProfile.getSignServiceId(),
                                    serviceName
                            ));
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
     * Set requestedCertAttributes from set metadataCustomCertAttribute.
     * @param supportAPIProfile Support service API profile configuration
     * @param friendlyName
     * @param requestedAttributeMap
     * @param requestedAttribute
     */
    private void setReqCertAttrFromMetaDataCustomCertAttr(SupportAPIProfile supportAPIProfile, StringBuilder friendlyName, Map<String, Object> requestedAttributeMap, ReducedMetadataImpl.RequestedAttribute requestedAttribute) throws BaseAPIException {
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
                        if(strings != null) {
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
                                msgLog.debug(String.format("required set to: %s", requestedAttributeMap.get("required")));
                            }

                            requestedAttributeMap.put("samlAttributeName", matchedSamlAttribute);
                            requestedAttributeMap.put("certAttributeRef", certAttributeRef);
                            msgLog.debug(String.format(
                                    "RequestedAttribute added with samlAttributeName '%s' and certAttributeRef '%s' for metadataCustomCertAttribute with friendlyName '%s' under profile '%s'",
                                    matchedSamlAttribute, certAttributeRef, key, supportAPIProfile.getRelatedProfile()
                            ));

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
            throw ErrorCode.INTERNAL_ERROR.toException(
                    v, messageSource
            );
        }
    }

    /**
     * Parse requestedCertAttributes from MetaData.
     * @param friendlyName
     * @param requestedAttributeMap
     * @param requestedAttribute
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
                    msgLog.debug(String.format("required set to: %s", requestedAttributeMap.get("required")));
                }

                msgLog.debug(String.format(
                        "RequestedAttribute added with samlAttributeName '%s', certAttributeRef '%s' and certNameType '%s' for friendlyName '%s'",
                        samlAttributeName,
                        certAttributeRef,
                        certNameType,
                        friendlyName.toString()
                ));
            }
        } catch (Exception e) {
            msgLog.error(String.format("Failed to automatically parse requestedCertAttributes from Metadata. %s", e.getMessage()));
            throw ErrorCode.INTERNAL_ERROR.toException(
                    String.format("Failed to automatically parse requestedCertAttributes from Metadata. %s", e.getMessage()),
                    messageSource
            );
        }
    }

    /**
     * Get the fieldName/friendlyName from either requestedAttributeType.friendlyName or requestedAttributeType.name
     * looked up via default values.
     * @param requestedAttributeType
     * @return friendlyName
     */
    static String determineFriendlyName(ReducedMetadataImpl.RequestedAttribute requestedAttributeType) {
        String friendlyName = requestedAttributeType != null && requestedAttributeType.getFriendlyName() != null
                ? requestedAttributeType.getFriendlyName().trim()
                : null;

        if (friendlyName != null && !friendlyName.isBlank() &&
                Fields.fieldNameToAttrRef.containsKey(friendlyName.toLowerCase())) {

            msgLog.debug(String.format("FriendlyName set from requestedAttributeType.friendlyName to: '%s'", friendlyName.trim()));
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
            msgLog.debug(String.format("FriendlyName set from requestedAttributeType.name to '%s'", tokenFriendlyName));
            return tokenFriendlyName;
        }

        msgLog.debug(String.format(
                "Unable to set any friendlyName from metadata for requestedAttribute with name '%s'",
                requestedAttributeType != null ? requestedAttributeType.getName() : null
        ));
        return null;
    }
}
