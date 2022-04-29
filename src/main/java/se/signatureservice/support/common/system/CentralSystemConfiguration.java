package se.signatureservice.support.common.system;

import java.util.List;

/**
 * Configuation items that is in common between frontend and backend systems
 *
 * Created by philip on 2017-07-22.
 */
public class CentralSystemConfiguration extends Configuration {

    /**
     * Reference to the related organisation
     */
    String relatedOrganisation;

    /**
     * Hidden version of organisation name, this should be generated automatically in later versions
     */
    String obfuscatedName;

    /**
     * A List of MetaData Entity Ids (Of Support Services) that is authorized to issue
     * sign requests to central system.
     */
    List<String> authorizedSupportServiceEntityIds;

    /**
     * A List of MetaData Entity Ids that is authorized to generate assertions
     * to the central system for related organisation.
     */
    List<String> authorizedIDPEntityIds;

    /**
     * Accepted clock skew in milliseconds. Used to handle unsynchronized clocks between systems, Default 15 minutes
     */
    long acceptedClockSkew = 15*60*1000; // 15 minutes

    /**
     * Maximum SignRequest validity, (Specified in condition element of SignRequestExtension) in milliseconds,
     * default is 10 minutes.
     */
    long maximumSignRequestValidity = 10*60*1000; // 10 minutes
}
