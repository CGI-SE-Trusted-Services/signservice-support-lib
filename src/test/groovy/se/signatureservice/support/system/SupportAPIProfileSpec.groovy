/************************************************************************
 *                                                                       *
 *  Signservice Support Lib                                              *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  (LGPL-3.0-or-later)                                                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.system

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
                authnContextClassRef: null,
                encryptionAlgorithmScheme: "RSA_PKCS1_5_WITH_AES256",
                timeStampServer: null,
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
                xadesCanonicalizationAlgorithmURI: "http://www.w3.org/2001/10/xml-exc-c14n#"
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
        profile.authnContextClassRef == null
        profile.encryptionAlgorithmScheme == "RSA_PKCS1_5_WITH_AES256"
        profile.timeStampServer == null
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
}
