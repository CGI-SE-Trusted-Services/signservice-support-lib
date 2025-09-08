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
package se.signatureservice.support.utils

import se.signatureservice.support.system.SupportAPIProfile
import spock.lang.Specification
import spock.lang.Unroll

class SupportLibraryUtilsSpec extends Specification {
    def "test generateTransactionId"(){
        when:
        List<String> transactionIds = []
        for(int i=0;i<1000;i++){
            transactionIds.add(SupportLibraryUtils.generateTransactionId())
        }

        then:
        transactionIds.each { String rs ->
            assert rs != null
            assert rs.length() >= 32
            assert transactionIds.findAll { it == rs }.size() == 1
        }
    }

    def "test generateReferenceId"() {
        when:
        List<String> referenceIds = []
        for(int i=0;i<1000;i++){
            referenceIds.add(SupportLibraryUtils.generateReferenceId())
        }

        then:
        referenceIds.each { String ri ->
            assert ri != null
            assert ri.length() >= 32
            assert referenceIds.findAll { it == ri }.size() == 1
        }
    }

    def "test generateStrongReferenceId"(){
        when:
        List<String> strongReferenceIds = []
        for(int i=0;i<1000;i++){
            String transactionId = SupportLibraryUtils.generateTransactionId()
            String referenceId = SupportLibraryUtils.generateReferenceId()
            strongReferenceIds.add(SupportLibraryUtils.generateStrongReferenceId(transactionId, referenceId))
        }

        then:
        strongReferenceIds.each { String sri ->
            assert sri != null
            assert sri.length() >= 32
            assert strongReferenceIds.findAll { it == sri }.size() == 1
        }
    }

    @Unroll
    def "test getUserIdAttributeMappings with userIdAttributeMapping #userIdAttributeMapping and defaultUserIdAttributeMapping #defaultUserIdAttributeMapping"() {
        given:
        def supportAPIProfile = Mock(SupportAPIProfile)
        supportAPIProfile.userIdAttributeMapping >> userIdAttributeMapping
        supportAPIProfile.defaultUserIdAttributeMapping >> defaultUserIdAttributeMapping

        when:
        def result = SupportLibraryUtils.getUserIdAttributeMappings(supportAPIProfile)

        then:
        result == expected

        where:
        userIdAttributeMapping | defaultUserIdAttributeMapping | expected
        "userIdMappingValue"   | "defaultMappingValue"         | ["userIdAttributeMapping": "userIdMappingValue", "defaultUserIdAttributeMapping": "defaultMappingValue"]
        "userIdMappingValue"   | null                          | ["userIdAttributeMapping": "userIdMappingValue"]
        null                   | "defaultMappingValue"         | ["defaultUserIdAttributeMapping": "defaultMappingValue"]
        ""                     | " "                           | [:]
        ""                     | null                          | [:]
        null                   | " "                           | [:]
        null                   | null                          | [:]
    }

    @Unroll
    def "test findAuthConfUserIdAttributeMappings with authenticationServiceId #authenticationServiceId"() {
        given:
        def supportAPIProfile = Mock(SupportAPIProfile)
        supportAPIProfile.trustedAuthenticationServices >> trustedAuthenticationServices

        when:
        def result = SupportLibraryUtils.findAuthConfUserIdAttributeMappings(authenticationServiceId, supportAPIProfile)

        then:
        result == expected

        where:
        authenticationServiceId | trustedAuthenticationServices                                                                                                   | expected
        "serviceId1"            | [idp1: [entityId: "serviceId1", userIdAttributeMapping: "value"], idp2: [entityId: "serviceId2", userIdAttributeMapping: null]] | [idp1: [entityId: "serviceId1", userIdAttributeMapping: "value"]]
        "serviceId1"            | [idp1: [userIdAttributeMapping: "value"], idp2: [entityId: "serviceId2", userIdAttributeMapping: null]]                         | [:]
        "serviceId1"            | [idp1: [entityId: "serviceId1", userIdAttributeMapping: "  "]]                                                                  | [:]
        "serviceId1"            | [idp1: [entityId: "serviceId1", userIdAttributeMapping: null]]                                                                  | [:]
        "serviceId1"            | [idp1: [entityId: "serviceId1", userIdAttributeMapping: 1]]                                                                     | [:]
        "serviceId1"            | [idp1: [entityId: "serviceId1", userIdAttributeMapping: ["1", "2"]]]                                                            | [:]
        "serviceId1"            | [idp1: [entityId: "serviceId1"]]                                                                                                | [:]
        "serviceId3"            | [idp1: [entityId: "serviceId1", userIdAttributeMapping: "value"]]                                                               | [:]
        "serviceId1"            | null                                                                                                                            | [:]
    }
}
