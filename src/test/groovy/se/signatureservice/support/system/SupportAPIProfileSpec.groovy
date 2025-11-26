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
package se.signatureservice.support.system

import eu.europa.esig.dss.enumerations.CertificationPermission
import se.signatureservice.configuration.common.InternalErrorException
import spock.lang.Specification

class SupportAPIProfileSpec extends Specification {
    def "test toMap"(){
        setup:
        Map profileData = [
                certificateType: "QC/SSCD",
                defaultAuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
                signerAttributes: null,
                padesSignatureLevel: "PAdES-BASELINE-B",
                signatureAlgorithm: "SHA256withECDSA",
                xadesSignaturePacking: "ENVELOPED",
                signMessageMustShow: "false",
                signServiceId: "https://signservice.thecompany.se/v1/metadata",
                cadesSignaturePacking: "ENVELOPING",
                validationPolicy: "basicpolicy",
                trustedAuthenticationServices: [
                        testIdp: [
                                entityId: "https://idp.cgi.com/v2/metadata",
                                defaultDisplayName: "Test iDP",
                                authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
                        ],
                        testIdp2: [
                                entityId: "https://idp2.cgi.com/v2/metadata",
                                defaultDisplayName: "Test iDP 2",
                                authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered",
                                userIdAttributeMapping: "urn:oid:1.2.752.201.3.4"
                        ],
                        testIdp3: [
                                entityId: "https://idp3.cgi.com/v2/metadata",
                                defaultDisplayName: "Test iDP 3",
                                authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
                                userIdAttributeMapping: "urn:oid:2.5.4.97"
                        ]
                ],
                authorizedCentralServiceEntityIds: null,
                signMessageMimeType: "TEXT",
                defaultAuthnContextClassRefs: null,
                useEncryptedSignMessage: false,
                userIdAttributeMapping: null,
                requestedCertAttributes: [
                        givenName: [
                                samlAttributeName:"urn:oid:2.5.4.42",
                                certAttributeRef: "2.5.4.42",
                                required: true
                        ],
                        sn: [
                                samlAttributeName: "urn:oid:2.5.4.4",
                                certAttributeRef: "2.5.4.4",
                                required: true
                        ],
                        serialNumber: [
                                samlAttributeName: "urn:oid:1.2.752.29.4.13",
                                certAttributeRef: "2.5.4.5",
                                required: true
                        ],
                        commonName: [
                                samlAttributeName: "urn:oid:2.16.840.1.113730.3.1.241",
                                certAttributeRef: "2.5.4.3",
                                required: false
                        ],
                        displayName: [
                                samlAttributeName: "urn:oid:2.16.840.1.113730.3.1.241",
                                certAttributeRef: "2.16.840.1.113730.3.1.241",
                                required:false
                        ],
                        c: [
                                samlAttributeName: "urn:oid:2.5.4.6",
                                certAttributeRef: "2.5.4.6",
                                required:false
                        ],
                        organizationName: [
                                samlAttributeName: "urn:oid:2.5.4.10",
                                certAttributeRef: "2.5.4.10",
                                required: false
                        ],
                        gender: [
                                samlAttributeName: "urn:oid:1.3.6.1.5.5.7.9.3",
                                certAttributeRef: "1.3.6.1.5.5.7.9.3",
                                certNameType: "sda",
                                required: false
                        ]
                ],
                signServiceRequestURL: "https://signservice.thecompany.se/signservice-frontend/request/4321a583928",
                signatureValidityMinutes: "10",
                enableAuthnProfile: false,
                padesSignaturePacking: "ENVELOPED",
                padesContentSize: 1337,
                authnContextClassRef: null,
                encryptionAlgorithmScheme: "RSA_PKCS1_5_WITH_AES256",
                enableAutomaticValidation: false,
                signatureValidityOverlapMinutes: "5",
                visibleSignature: [
                        enable: true,
                        backgroundColor: "#ff0000",
                        showHeadline: true,
                        headlineText: "This is the headline"
                ],
                relatedProfile: "testProfileECDSA",
                authorizedConsumerURLs: [
                        "https://localhost",
                        "http://localhost"
                ],
                defaultUserIdAttributeMapping: "urn:oid:1.2.752.29.4.13",
                signRequestExtensionVersion: "1.5",
                userDisplayNameAttribute: "name",
                xadesXPathLocationString: "node()[not(ancestor-or-self::*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#'])]",
                cadesSignatureLevel: "CAdES-BASELINE-B",
                enableEnhancedLogging: false,
                signRequester: "TheCompany",
                xadesSignatureLevel: "XAdES-BASELINE-B",
                xadesCanonicalizationAlgorithmURI: "http://www.w3.org/2001/10/xml-exc-c14n#",
                timeStamp: [
                        url: "https://timestamp.random.local",
                        username: "randomuser",
                        password: "randompassword",
                        keyStorePath: "/config/keystore.p12",
                        keyStorePassword: "123456",
                        keyStoreType: "PKCS12",
                        trustStorePath: "/config/truststore.jks",
                        trustStorePassword: "654321",
                        trustStoreType: "JKS",
                        proxyHost: "randomproxy.local",
                        proxyPort: 443,
                        proxyScheme: "https",
                        proxyUser: "proxyuser",
                        proxyPassword: "123123",
                        proxyExcludedHosts: "localhost,google.com",
                        sslProtocol: "TLS v1.3"
                ]
        ]

        when:
        SupportAPIProfile profile = SupportAPIProfile.fromMap(profileData)

        then:
        profile.certificateType == "QC/SSCD"
        profile.defaultAuthnContextClassRef == "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
        profile.signerAttributes == null
        profile.padesSignatureLevel == "PAdES-BASELINE-B"
        profile.signatureAlgorithm == "SHA256withECDSA"
        profile.xadesSignaturePacking == "ENVELOPED"
        !profile.signMessageMustShow
        profile.signServiceId == "https://signservice.thecompany.se/v1/metadata"
        profile.cadesSignaturePacking == "ENVELOPING"
        profile.validationPolicy == "basicpolicy"
        profile.trustedAuthenticationServices.size() == 3
        profile.trustedAuthenticationServices["testIdp"]["entityId"] == "https://idp.cgi.com/v2/metadata"
        profile.trustedAuthenticationServices["testIdp"]["defaultDisplayName"] == "Test iDP"
        profile.trustedAuthenticationServices["testIdp"]["authnContextClassRef"] == "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
        profile.trustedAuthenticationServices["testIdp2"]["entityId"] == "https://idp2.cgi.com/v2/metadata"
        profile.trustedAuthenticationServices["testIdp2"]["defaultDisplayName"] == "Test iDP 2"
        profile.trustedAuthenticationServices["testIdp2"]["authnContextClassRef"] == "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered"
        profile.trustedAuthenticationServices["testIdp2"]["userIdAttributeMapping"] == "urn:oid:1.2.752.201.3.4"
        profile.trustedAuthenticationServices["testIdp3"]["entityId"] == "https://idp3.cgi.com/v2/metadata"
        profile.trustedAuthenticationServices["testIdp3"]["defaultDisplayName"] == "Test iDP 3"
        profile.trustedAuthenticationServices["testIdp3"]["authnContextClassRef"] == "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
        profile.trustedAuthenticationServices["testIdp3"]["userIdAttributeMapping"] == "urn:oid:2.5.4.97"
        profile.signServiceRequestURL == "https://signservice.thecompany.se/signservice-frontend/request/4321a583928"
        profile.signatureValidityMinutes == 10
        !profile.enableAuthnProfile
        profile.padesSignaturePacking == "ENVELOPED"
        profile.padesContentSize == 1337
        profile.authnContextClassRef == null
        profile.encryptionAlgorithmScheme == "RSA_PKCS1_5_WITH_AES256"
        !profile.enableAutomaticValidation
        profile.signatureValidityOverlapMinutes == 5
        profile.visibleSignature.enable
        profile.visibleSignature.backgroundColor == "#ff0000"
        profile.visibleSignature.showHeadline
        profile.visibleSignature.headlineText == "This is the headline"
        profile.relatedProfile == "testProfileECDSA"
        profile.authorizedConsumerURLs.size() == 2
        profile.authorizedConsumerURLs.contains("https://localhost")
        profile.authorizedConsumerURLs.contains("http://localhost")
        profile.defaultUserIdAttributeMapping == "urn:oid:1.2.752.29.4.13"
        profile.signRequestExtensionVersion == "1.5"
        profile.userDisplayNameAttribute == "name"
        profile.xadesXPathLocationString == "node()[not(ancestor-or-self::*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#'])]"
        profile.cadesSignatureLevel == "CAdES-BASELINE-B"
        !profile.enableEnhancedLogging
        profile.signRequester == "TheCompany"
        profile.xadesSignatureLevel == "XAdES-BASELINE-B"
        profile.xadesCanonicalizationAlgorithmURI == "http://www.w3.org/2001/10/xml-exc-c14n#"
        profile.timeStamp.url == "https://timestamp.random.local"
        profile.timeStamp.username ==  "randomuser"
        profile.timeStamp.password == "randompassword"
        profile.timeStamp.keyStorePath == "/config/keystore.p12"
        profile.timeStamp.keyStorePassword == "123456"
        profile.timeStamp.keyStoreType == "PKCS12"
        profile.timeStamp.trustStorePath == "/config/truststore.jks"
        profile.timeStamp.trustStorePassword == "654321"
        profile.timeStamp.trustStoreType == "JKS"
        profile.timeStamp.proxyHost == "randomproxy.local"
        profile.timeStamp.proxyScheme == "https"
        profile.timeStamp.proxyPort == 443
        profile.timeStamp.proxyUser == "proxyuser"
        profile.timeStamp.proxyPassword == "123123"
        profile.timeStamp.proxyExcludedHosts == "localhost,google.com"
        profile.timeStamp.sslProtocol == "TLS v1.3"
    }

    def "verify default Support API profile settings"() {
        when:
        SupportAPIProfile profile = new SupportAPIProfile.Builder().build()

        then:
        profile.xadesSignatureLevel == "XAdES-BASELINE-B"
        profile.xadesSignaturePacking == "ENVELOPED"
        profile.xadesCanonicalizationAlgorithmURI == "http://www.w3.org/2001/10/xml-exc-c14n#"
        profile.xadesXPathLocationString == "node()[not(self::Signature)]"
        profile.padesSignatureLevel == "PAdES-BASELINE-B"
        profile.padesSignaturePacking == "ENVELOPED"
        profile.cadesSignatureLevel == "CAdES-BASELINE-B"
        profile.cadesSignaturePacking == "ENVELOPING"
        profile.signatureValidityOverlapMinutes == 0
        profile.signatureValidityMinutes == 5
        profile.signatureAlgorithm == "SHA256withRSA"
        profile.encryptionAlgorithmScheme == "RSA_PKCS1_5_WITH_AES256"
        !profile.useEncryptedSignMessage
        !profile.signMessageMustShow
        profile.signMessageMimeType == "TEXT"
        profile.defaultUserIdAttributeMapping == "urn:oid:1.2.752.29.4.13"
        profile.signRequestExtensionVersion == "1.5"
        profile.validationPolicy == "/policy/basicpolicy.xml"
    }

    def "test to add individual signer attributes"(){
        when:
        SupportAPIProfile profile = new SupportAPIProfile.Builder()
            .addSignerAttribute("testattribute1", "urn:oid:2.5.4.42", "userattribute1", true)
            .addSignerAttribute("testattribute2", "urn:oid:2.5.4.10", "userattribute2", false)
            .build()

        then:
        profile.signerAttributes != null
        profile.signerAttributes["testattribute1"] != null
        profile.signerAttributes["testattribute1"]["samlAttributeName"] == "urn:oid:2.5.4.42"
        profile.signerAttributes["testattribute1"]["userAttributeMapping"] == "userattribute1"
        profile.signerAttributes["testattribute1"]["required"] == "true"
        profile.signerAttributes["testattribute2"] != null
        profile.signerAttributes["testattribute2"]["samlAttributeName"] == "urn:oid:2.5.4.10"
        profile.signerAttributes["testattribute2"]["userAttributeMapping"] == "userattribute2"
        profile.signerAttributes["testattribute2"]["required"] == "false"
    }

    def "test pdfCertificationPermission builder method sets correct permission"() {
        when: "A SupportAPIProfile is built with a specific PDF certification permission level"
        SupportAPIProfile profile = new SupportAPIProfile.Builder()
                .pdfCertificationPermission(level)
                .build()

        then: "The profile should have the correct CertificationPermission enum set"
        profile.getPdfCertificationPermission() == expectedPermission

        where:
        level | expectedPermission
        1     | CertificationPermission.NO_CHANGE_PERMITTED
        2     | CertificationPermission.MINIMAL_CHANGES_PERMITTED
        3     | CertificationPermission.CHANGES_PERMITTED
    }

    def "test pdfCertificationPermission builder method with invalid level throws exception"() {
        when: "A SupportAPIProfile is built with an invalid PDF certification permission level"
        new SupportAPIProfile.Builder()
                .pdfCertificationPermission(invalidLevel)
                .build()

        then: "An InternalErrorException should be thrown"
        thrown(InternalErrorException)

        where:
        invalidLevel | _
        0            | _
        4            | _
        -1           | _
    }

    def "test pdfCertificationPermission builder method when no permission is set"() {
        when: "A SupportAPIProfile is built without setting PDF certification permission"
        SupportAPIProfile profile = new SupportAPIProfile.Builder().build()

        then: "The pdfCertificationPermission should be null by default"
        profile.getPdfCertificationPermission() == null
    }
}
