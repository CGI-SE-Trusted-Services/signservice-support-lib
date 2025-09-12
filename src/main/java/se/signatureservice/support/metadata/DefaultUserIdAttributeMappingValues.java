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

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Constants class contains a set of predefined, immutable string constants.
 */
public class DefaultUserIdAttributeMappingValues {
    static final List<String> VALUES = List.of(
            "urn:oid:1.2.752.29.4.13",
            "urn:oid:1.2.752.201.3.4",
            "http://sambi.se/attributes/1/personalIdentityNumber",
            "http://sambi.se/attributes/1/employeeHsaId",
            "http://sambi.se/attributes/1/organizationIdentifier",
            "urn:orgAffiliation"
            );

    /**
     * Finds matches in CONSTANTS and, optionally, profileConstants.
     *
     * @param values List of strings to check for matches.
     * @return List of matching strings.
     */
    public static List<String> findMatches(List<String> values) {
        return findMatches(values, null);
    }

    /**
     * Finds matches in CONSTANTS and, optionally, profileConstants.
     *
     * @param values List of strings to check for matches.
     * @param profileConstants Optional set of constants to check for matches.
     * @return List of matching strings.
     */
    public static List<String> findMatches(List<String> values, List<String> profileConstants) {
        if (values == null || values.isEmpty()) {
            return Collections.emptyList();
        }

        var constants = profileConstants != null ? profileConstants : VALUES;
        var trimmedConstants = constants
                .stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .collect(Collectors.toList());

        var trimmedValues = values.stream()
                .filter(Objects::nonNull)
                .map(String::trim);

        return trimmedValues.filter(trimmedConstants::contains).collect(Collectors.toList());
    }
}
