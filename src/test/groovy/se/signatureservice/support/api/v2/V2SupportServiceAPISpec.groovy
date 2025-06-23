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
package se.signatureservice.support.api.v2

import com.fasterxml.jackson.databind.ObjectMapper
import eu.europa.esig.dss.pades.PAdESSignatureParameters
import eu.europa.esig.dss.service.crl.OnlineCRLSource
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader
import eu.europa.esig.dss.service.http.proxy.ProxyConfig
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import groovy.xml.XmlSlurper
import groovy.yaml.YamlSlurper
import org.bouncycastle.util.encoders.Base64
import se.signatureservice.configuration.support.system.Constants
import se.signatureservice.configuration.support.system.VisibleSignatureConfig
import se.signatureservice.messages.ContextMessageSecurityProvider
import se.signatureservice.messages.MessageSecurityProvider
import se.signatureservice.messages.dss1.core.jaxb.Result
import se.signatureservice.messages.dss1.core.jaxb.SignResponse
import se.signatureservice.messages.sweeid2.dssextenstions1_1.SigType
import se.signatureservice.messages.sweeid2.dssextenstions1_1.SweEID2DSSExtensionsMessageParser
import se.signatureservice.messages.utils.CertUtils
import se.signatureservice.support.common.cache.SimpleCacheProvider
import se.signatureservice.support.signer.SignatureAttributePreProcessor
import se.signatureservice.support.system.SupportAPIProfile
import se.signatureservice.support.system.TransactionState
import se.signatureservice.support.utils.SupportLibraryUtils
import spock.lang.Specification
import spock.lang.Unroll

import java.security.cert.X509Certificate
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.time.Duration
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

import static se.signatureservice.support.api.AvailableSignatureAttributes.*

/**
 * Unit tests for {@link se.signatureservice.support.api.v2.V2SupportServiceAPI}.
 */
class V2SupportServiceAPISpec extends Specification {
    static V2SupportServiceAPI supportServiceAPI
    static List<Object> testDocuments = []
    static YamlSlurper yamlSlurper = new YamlSlurper()

    static SupportAPIProfile testProfile1 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile1.yml")) as Map)
    static SupportAPIProfile testProfile2 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile2.yml")) as Map)
    static SupportAPIProfile testProfile3 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile3.yml")) as Map)
    static SupportAPIProfile testProfile4 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile4.yml")) as Map)
    static SupportAPIProfile testProfile5 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile5.yml")) as Map)
    static SupportAPIProfile testProfile6 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile6.yml")) as Map)
    static SupportAPIProfile testProfile7 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile7.yml")) as Map)
    static SupportAPIProfile testProfile8 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile8.yml")) as Map)
    static SupportAPIProfile testProfile9 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile9.yml")) as Map)
    static SupportAPIProfile testProfile10 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile10.yml")) as Map)
    static SupportAPIProfile testProfile11 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile11.yml")) as Map)

    static X509Certificate testRecipientCert

    static Document testSignedPDFDocument
    static Document testSignedXMLDocument
    static Document testSignedCMSDocument
    static Document testSignedXMLNonETSIDocument
    static Document testUnsignedPDFDocument
    static Document testUnsignedXMLDocument
    static Document testUnsignedCMSDocument

    void setupSpec(){
        CertUtils.installBCProvider()
        testRecipientCert = CertUtils.getCertfromByteArray(new File("src/test/resources/testrecipient.cer").bytes)

        supportServiceAPI = new V2SupportServiceAPI.Builder()
            .messageSecurityProvider(SupportLibraryUtils.createSimpleMessageSecurityProvider(
                    "src/test/resources/keystore.jks",
                    "TSWCeC",
                    "8af76eae8e1a201;cn=mock issuing ca,o=mockasiner ab,c=se",
                    "src/test/resources/truststore.jks",
                    "foo123"
            ))
            .cacheProvider(new SimpleCacheProvider())
            .addSignMessageRecipient("https://m00-mg-local.idpst.funktionstjanster.se/samlv2/idp/metadata/6/7", testRecipientCert)
            .trustedCertificateSource(new KeyStoreCertificateSource("src/test/resources/validation-truststore.jks", "jks", "foo123".toCharArray()))
            .build() as V2SupportServiceAPI

        testDocuments.add(new DocumentSigningRequest(referenceId: "123456", type: "application/pdf", name: "testdocument.pdf", data: new File("src/test/resources/testdocument.pdf").bytes))
        testDocuments.add(new DocumentSigningRequest(referenceId: "234567", type: "text/xml", name: "testdocument.xml", data: new File("src/test/resources/testdocument.xml").bytes))
        testDocuments.add(new DocumentSigningRequest(referenceId: "345678", type: "application/octet-stream", name: "testdocument.doc", data: new File("src/test/resources/testdocument.doc").bytes))

        testSignedPDFDocument = new Document(referenceId: "123456", type: "application/pdf", name: "testdocument-signed.pdf", data: new File("src/test/resources/signed-documents/testdocument-signed.pdf").bytes)
        testSignedXMLDocument = new Document(referenceId: "234567", type: "text/xml", name: "testdocument-signed.xml", data: new File("src/test/resources/signed-documents/testdocument-signed.xml").bytes)
        testSignedCMSDocument = new Document(referenceId: "345678", type: "application/msword", name: "testdocument-signed.doc", data: new File("src/test/resources/signed-documents/testdocument-signed.doc").bytes)
        testSignedXMLNonETSIDocument = new Document(referenceId: "456789", type: "text/xml", name: "testdocument_NonETSI.xml", data: new File("src/test/resources/signed-documents/testdocument_NonETSI.xml").bytes)
        testUnsignedPDFDocument = new Document(referenceId: "123456", type: "application/pdf", name: "testdocument.pdf", data: new File("src/test/resources/testdocument.pdf").bytes)
        testUnsignedXMLDocument = new Document(referenceId: "234567", type: "text/xml", name: "testdocument.xml", data: new File("src/test/resources/testdocument.xml").bytes)
        testUnsignedCMSDocument = new Document(referenceId: "345678", type: "application/msword", name: "testdocument.doc", data: new File("src/test/resources/testdocument.doc").bytes)
    }

    @Unroll
    void "test generateSignRequest with RSA"() {
        setup:
        User user = new User(userId: "190102030010")
        ContextMessageSecurityProvider.Context context = null
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments

        when:
        byte[] response = supportServiceAPI.generateSignRequest(
                context,
                "a864b33d-244a-4072-b540-0b29e2e7f40b",
                documents,
                "You want to sign?",
                user,
                "https://idp.cgi.com/v2/metadata",
                null,
                "https://localhost:8080/response",
                testProfile1,
                null,
                null
        )

        then:
        response != null
        println new String(Base64.decode(response), "UTF-8")

        def signRequest = new XmlSlurper().parse(new ByteArrayInputStream(Base64.decode(response)))
        signRequest.@Profile == "http://id.elegnamnden.se/csig/1.1/dss-ext/profile"
        signRequest.@RequestID == "a864b33d-244a-4072-b540-0b29e2e7f40b"
        signRequest.OptionalInputs != null
        signRequest.OptionalInputs.SignRequestExtension != null
        signRequest.OptionalInputs.SignRequestExtension.RequestTime != null
        getMinutesBetween(signRequest.OptionalInputs.SignRequestExtension.RequestTime as String, new Date()) < 5
        signRequest.OptionalInputs.SignRequestExtension.Conditions.@NotBefore != null
        signRequest.OptionalInputs.SignRequestExtension.Conditions.@NotOnOrAfter != null
        getMinutesBetween(signRequest.OptionalInputs.SignRequestExtension.Conditions.@NotBefore as String, signRequest.OptionalInputs.SignRequestExtension.RequestTime as String) == 5
        getMinutesBetween(signRequest.OptionalInputs.SignRequestExtension.Conditions.@NotBefore as String, signRequest.OptionalInputs.SignRequestExtension.Conditions.@NotOnOrAfter as String) == 15
        signRequest.OptionalInputs.SignRequestExtension.Conditions.AudienceRestriction != null
        signRequest.OptionalInputs.SignRequestExtension.Conditions.AudienceRestriction.Audience == "https://localhost:8080/response"
        signRequest.OptionalInputs.SignRequestExtension.Signer != null
        signRequest.OptionalInputs.SignRequestExtension.Signer.Attribute.@Name == "urn:oid:1.2.752.29.4.13"
        signRequest.OptionalInputs.SignRequestExtension.Signer.Attribute.AttributeValue == "190102030010"
        signRequest.OptionalInputs.SignRequestExtension.IdentityProvider == "https://idp.cgi.com/v2/metadata"
        signRequest.OptionalInputs.SignRequestExtension.SignRequester == "TheCompany"
        signRequest.OptionalInputs.SignRequestExtension.SignService == "https://signservice.thecompany.se/v1/metadata"
        signRequest.OptionalInputs.SignRequestExtension.RequestedSignatureAlgorithm == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties != null
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.@CertType == "QC/SSCD"

        def authnContextClassRefs = signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.AuthnContextClassRef.iterator().collect { it.text() }
        authnContextClassRefs.size() == 1
        authnContextClassRefs.contains("urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI")

        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.children().size() == 8
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.42" && it.@FriendlyName == "givenName" && it.@Required == "true"}.SamlAttributeName == "urn:oid:2.5.4.42"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.4" && it.@FriendlyName == "sn" && it.@Required == "true"}.SamlAttributeName == "urn:oid:2.5.4.4"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.5" && it.@FriendlyName == "serialNumber" && it.@Required == "true"}.SamlAttributeName == "urn:oid:1.2.752.29.4.13"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.3" && it.@FriendlyName == "commonName" && it.@Required == "false"}.SamlAttributeName == "urn:oid:2.16.840.1.113730.3.1.241"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.16.840.1.113730.3.1.241" && it.@FriendlyName == "displayName" && it.@Required == "false"}.SamlAttributeName == "urn:oid:2.16.840.1.113730.3.1.241"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.6" && it.@FriendlyName == "c" && it.@Required == "false"}.SamlAttributeName == "urn:oid:2.5.4.6"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.10" && it.@FriendlyName == "organizationName" && it.@Required == "false"}.SamlAttributeName == "urn:oid:2.5.4.10"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "1.3.6.1.5.5.7.9.3" && it.@FriendlyName == "gender" && it.@CertNameType == "sda" && it.@Required == "false"}.SamlAttributeName == "urn:oid:1.3.6.1.5.5.7.9.3"
        signRequest.OptionalInputs.SignRequestExtension.SignMessage != null
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.@DisplayEntity == "https://idp.cgi.com/v2/metadata"
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.Message != null
        new String(Base64.decode((signRequest.OptionalInputs.SignRequestExtension.SignMessage.Message as String).bytes)) == "You want to sign?"
        signRequest.OptionalInputs.Signature != null
        signRequest.InputDocuments != null
        signRequest.InputDocuments.Other != null
        signRequest.InputDocuments.Other.SignTasks.children().size() == 3
        signRequest.InputDocuments.Other.SignTasks.SignTaskData.find{it.@SigType=="PDF"}.ToBeSignedBytes != null
        signRequest.InputDocuments.Other.SignTasks.SignTaskData.find{it.@SigType=="CMS"}.ToBeSignedBytes != null
        def signedInfo = new XmlSlurper().parseText(new String(Base64.decode((signRequest.InputDocuments.Other.SignTasks.SignTaskData.find{it.@SigType=="XML"}.ToBeSignedBytes as String).bytes)))
        signedInfo.CanonicalizationMethod.@Algorithm == "http://www.w3.org/2001/10/xml-exc-c14n#"
        signedInfo.SignatureMethod.@Algorithm == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        signedInfo.Reference.size() == 2
        signedInfo.Reference[0].@URI == ""
        signedInfo.Reference[0].@Type == ""
        signedInfo.Reference[0].Transforms.children().size() == 2
        signedInfo.Reference[0].Transforms.Transform[0].@Algorithm == "http://www.w3.org/2002/06/xmldsig-filter2"
        signedInfo.Reference[0].Transforms.Transform[1].@Algorithm == "http://www.w3.org/2001/10/xml-exc-c14n#"
        signedInfo.Reference[0].DigestMethod.@Algorithm == "http://www.w3.org/2001/04/xmlenc#sha256"
        signedInfo.Reference[0].DigestValue != null
        signedInfo.Reference[1].@URI != ""
        signedInfo.Reference[1].@Type == "http://uri.etsi.org/01903#SignedProperties"
        signedInfo.Reference[1].Transforms.children().size() == 1
        signedInfo.Reference[1].Transforms.Transform[0].@Algorithm == "http://www.w3.org/2001/10/xml-exc-c14n#"
        signedInfo.Reference[1].DigestMethod.@Algorithm == "http://www.w3.org/2001/04/xmlenc#sha256"
        signedInfo.Reference[1].DigestValue != null
    }

    @Unroll
    void "test generateSignRequest overriding authnContextClassRefs #overrideAuthnContextClassRefs"() {
        setup:
        User user = new User(userId: "190102030010")
        ContextMessageSecurityProvider.Context context = null
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments

        when:
        byte[] response = supportServiceAPI.generateSignRequest(
                context,
                "a864b33d-244a-4072-b540-0b29e2e7f40b",
                documents,
                "You want to sign?",
                user,
                "https://idp.cgi.com/v2/metadata",
                overrideAuthnContextClassRefs,
                "https://localhost:8080/response",
                testProfile1,
                null,
                null
        )

        then:
        response != null
        println new String(Base64.decode(response), "UTF-8")

        def signRequest = new XmlSlurper().parse(new ByteArrayInputStream(Base64.decode(response)))
        signRequest.@Profile == "http://id.elegnamnden.se/csig/1.1/dss-ext/profile"
        signRequest.@RequestID == "a864b33d-244a-4072-b540-0b29e2e7f40b"
        signRequest.OptionalInputs != null
        signRequest.OptionalInputs.SignRequestExtension != null
        signRequest.OptionalInputs.SignRequestExtension.RequestTime != null

        def authnContextClassRefs = signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.AuthnContextClassRef.iterator().collect { it.text() }
        authnContextClassRefs.size() == expectedAuthnContextClassRefs.size()
        expectedAuthnContextClassRefs.every {authnContextClassRefs.contains(it)}

        where:
        overrideAuthnContextClassRefs          | expectedAuthnContextClassRefs
        null                                   | ["urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"]
        ["Ref:A", "Ref:B"]                     | ["Ref:A", "Ref:B"]
    }

    @Unroll
    void "test generateSignRequest with ECDSA"() {
        setup:
        User user = new User(userId: "190102030010")
        ContextMessageSecurityProvider.Context context = new ContextMessageSecurityProvider.Context(Constants.CONTEXT_USAGE_SIGNREQUEST)
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments

        when:
        byte[] response = supportServiceAPI.generateSignRequest(
                context,
                "b8ae1fba-b66c-4f97-8d92-c78f3d58283f",
                documents,
                "You want to sign?",
                user,
                "https://idp.cgi.com/v2/metadata",
                null,
                "https://localhost:8080/response",
                testProfile2,
                null,
                null
        )

        then:
        response != null
        println new String(Base64.decode(response), "UTF-8")

        def signRequest = new XmlSlurper().parse(new ByteArrayInputStream(Base64.decode(response)))
        signRequest.@Profile == "http://id.elegnamnden.se/csig/1.1/dss-ext/profile"
        signRequest.@RequestID == "b8ae1fba-b66c-4f97-8d92-c78f3d58283f"
        signRequest.OptionalInputs != null
        signRequest.OptionalInputs.SignRequestExtension != null
        signRequest.OptionalInputs.SignRequestExtension.RequestTime != null
        getMinutesBetween(signRequest.OptionalInputs.SignRequestExtension.RequestTime as String, new Date()) < 5
        signRequest.OptionalInputs.SignRequestExtension.Conditions.@NotBefore != null
        signRequest.OptionalInputs.SignRequestExtension.Conditions.@NotOnOrAfter != null
        getMinutesBetween(signRequest.OptionalInputs.SignRequestExtension.Conditions.@NotBefore as String, signRequest.OptionalInputs.SignRequestExtension.RequestTime as String) == 5
        getMinutesBetween(signRequest.OptionalInputs.SignRequestExtension.Conditions.@NotBefore as String, signRequest.OptionalInputs.SignRequestExtension.Conditions.@NotOnOrAfter as String) == 15
        signRequest.OptionalInputs.SignRequestExtension.Conditions.AudienceRestriction != null
        signRequest.OptionalInputs.SignRequestExtension.Conditions.AudienceRestriction.Audience == "https://localhost:8080/response"
        signRequest.OptionalInputs.SignRequestExtension.Signer != null
        signRequest.OptionalInputs.SignRequestExtension.Signer.Attribute.@Name == "urn:oid:1.2.752.29.4.13"
        signRequest.OptionalInputs.SignRequestExtension.Signer.Attribute.AttributeValue == "190102030010"
        signRequest.OptionalInputs.SignRequestExtension.IdentityProvider == "https://idp.cgi.com/v2/metadata"
        signRequest.OptionalInputs.SignRequestExtension.SignRequester == "TheCompany"
        signRequest.OptionalInputs.SignRequestExtension.SignService == "https://signservice.thecompany.se/v1/metadata"
        signRequest.OptionalInputs.SignRequestExtension.RequestedSignatureAlgorithm == "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties != null
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.@CertType == "QC/SSCD"

        def authnContextClassRefs = signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.AuthnContextClassRef.iterator().collect { it.text() }
        authnContextClassRefs.size() == 1
        authnContextClassRefs.contains("urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos")

        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.children().size() == 8
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.42" && it.@FriendlyName == "givenName" && it.@Required == "true"}.SamlAttributeName == "urn:oid:2.5.4.42"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.4" && it.@FriendlyName == "sn" && it.@Required == "true"}.SamlAttributeName == "urn:oid:2.5.4.4"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.5" && it.@FriendlyName == "serialNumber" && it.@Required == "true"}.SamlAttributeName == "urn:oid:1.2.752.29.4.13"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.3" && it.@FriendlyName == "commonName" && it.@Required == "false"}.SamlAttributeName == "urn:oid:2.16.840.1.113730.3.1.241"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.16.840.1.113730.3.1.241" && it.@FriendlyName == "displayName" && it.@Required == "false"}.SamlAttributeName == "urn:oid:2.16.840.1.113730.3.1.241"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.6" && it.@FriendlyName == "c" && it.@Required == "false"}.SamlAttributeName == "urn:oid:2.5.4.6"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.10" && it.@FriendlyName == "organizationName" && it.@Required == "false"}.SamlAttributeName == "urn:oid:2.5.4.10"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "1.3.6.1.5.5.7.9.3" && it.@FriendlyName == "gender" && it.@CertNameType == "sda" && it.@Required == "false"}.SamlAttributeName == "urn:oid:1.3.6.1.5.5.7.9.3"
        signRequest.OptionalInputs.SignRequestExtension.SignMessage != null
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.@DisplayEntity == "https://idp.cgi.com/v2/metadata"
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.Message != null
        new String(Base64.decode((signRequest.OptionalInputs.SignRequestExtension.SignMessage.Message as String).bytes)) == "You want to sign?"
        signRequest.OptionalInputs.Signature != null
        signRequest.InputDocuments != null
        signRequest.InputDocuments.Other != null
        signRequest.InputDocuments.Other.SignTasks.children().size() == 3
        signRequest.InputDocuments.Other.SignTasks.SignTaskData.find{it.@SigType=="PDF"}.ToBeSignedBytes != null
        signRequest.InputDocuments.Other.SignTasks.SignTaskData.find{it.@SigType=="CMS"}.ToBeSignedBytes != null
        def signedInfo = new XmlSlurper().parseText(new String(Base64.decode((signRequest.InputDocuments.Other.SignTasks.SignTaskData.find{it.@SigType=="XML"}.ToBeSignedBytes as String).bytes)))
        signedInfo.CanonicalizationMethod.@Algorithm == "http://www.w3.org/2001/10/xml-exc-c14n#"
        signedInfo.SignatureMethod.@Algorithm == "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        signedInfo.Reference.size() == 2
        signedInfo.Reference[0].@URI == ""
        signedInfo.Reference[0].@Type == ""
        signedInfo.Reference[0].Transforms.children().size() == 2
        signedInfo.Reference[0].Transforms.Transform[0].@Algorithm == "http://www.w3.org/2002/06/xmldsig-filter2"
        signedInfo.Reference[0].Transforms.Transform[1].@Algorithm == "http://www.w3.org/2001/10/xml-exc-c14n#"
        signedInfo.Reference[0].DigestMethod.@Algorithm == "http://www.w3.org/2001/04/xmlenc#sha256"
        signedInfo.Reference[0].DigestValue != null
        signedInfo.Reference[1].@URI != ""
        signedInfo.Reference[1].@Type == "http://uri.etsi.org/01903#SignedProperties"
        signedInfo.Reference[1].Transforms.children().size() == 1
        signedInfo.Reference[1].Transforms.Transform[0].@Algorithm == "http://www.w3.org/2001/10/xml-exc-c14n#"
        signedInfo.Reference[1].DigestMethod.@Algorithm == "http://www.w3.org/2001/04/xmlenc#sha256"
        signedInfo.Reference[1].DigestValue != null
    }

    @Unroll
    void "test generateSignRequest with encrypted sign message"() {
        setup:
        User user = new User(userId: "190102030010")
        ContextMessageSecurityProvider.Context context = new ContextMessageSecurityProvider.Context(Constants.CONTEXT_USAGE_SIGNREQUEST,"testProfileRSAEncSigMsg")
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments
        String transactionId = UUID.randomUUID().toString()

        when:
        byte[] response = supportServiceAPI.generateSignRequest(
                context,
                transactionId,
                documents,
                "You want to sign?",
                user,
                "https://m00-mg-local.idpst.funktionstjanster.se/samlv2/idp/metadata/6/7",
                null,
                "https://localhost:8080/response",
                testProfile3,
                null,
                null
        )

        then:
        response != null
        println new String(Base64.decode(response), "UTF-8")

        def signRequest = new XmlSlurper().parse(new ByteArrayInputStream(Base64.decode(response)))
        signRequest?.OptionalInputs?.SignRequestExtension?.SignMessage != null
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.@DisplayEntity == "https://m00-mg-local.idpst.funktionstjanster.se/samlv2/idp/metadata/6/7"
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.@MimeType == "text/html"
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.@MustShow == "true"

        // Verify that we have an encrypted message along with an encrypted key with
        // keyinfo matching specified SAML entity
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.EncryptedMessage != null
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.EncryptedMessage.EncryptedData?.EncryptionMethod?.@Algorithm == "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.EncryptedMessage.EncryptedData?.KeyInfo?.EncryptedKey?.EncryptionMethod?.@Algorithm == "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.EncryptedMessage.EncryptedData?.KeyInfo?.EncryptedKey?.KeyInfo.X509Data?.X509Certificate == new String(Base64.encode(testRecipientCert.encoded))
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.EncryptedMessage.EncryptedData?.KeyInfo?.EncryptedKey?.CipherData?.CipherValue != null
        signRequest.OptionalInputs.SignRequestExtension.SignMessage.EncryptedMessage.EncryptedData?.CipherData?.CipherValue != null
    }


    @Unroll
    void "test generateSignRequest with multiple samlAttributeNames in the profileConfig"() {
        setup:
        User user = new User(userId: "190102030010", userAttributes: [
                new Attribute(key: "employeehsaid", value: "123456")
        ])
        ContextMessageSecurityProvider.Context context = null
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments

        when:
        byte[] response = supportServiceAPI.generateSignRequest(
            context,
            "a864b33d-244a-4072-b540-0b29e2e7f40b",
            documents,
            "You want to sign?",
            user,
            "https://idp.cgi.com/v2/metadata",
            null,
            "https://localhost:8080/response",
            testProfile4,
            null,
            null
        )

        then:
        response != null
        println new String(Base64.decode(response), "UTF-8")
        def signRequest = new XmlSlurper().parse(new ByteArrayInputStream(Base64.decode(response)))
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.children().size() == 4
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.42" && it.@FriendlyName == "givenName" && it.@Required == "true"}.SamlAttributeName == "urn:oid:2.5.4.42"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.5.4.4" && it.@FriendlyName == "sn" && it.@Required == "true"}.SamlAttributeName == "urn:oid:2.5.4.4"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute.find{it.@CertAttributeRef == "2.16.840.1.113730.3.1.241" && it.@FriendlyName == "displayName" && it.@Required == "true"}.SamlAttributeName == "urn:oid:2.16.840.1.113730.3.1.241"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute[3].@FriendlyName == "serialNumber"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute[3].@Required == "true"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute[3].@CertAttributeRef == "2.5.4.5"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute[3].SamlAttributeName[0] == "urn:oid:1.2.752.29.4.13"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute[3].SamlAttributeName[0].@Order == "1"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute[3].SamlAttributeName[1] == "urn:oid:1.2.752.29.6.2.1"
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.RequestedCertAttributes.RequestedCertAttribute[3].SamlAttributeName[1].@Order == "0"
    }

    @Unroll
    void "test generateSignRequest with invalid order types in the profileConfig"() {
        setup:
        User user = new User(userId: "190102030010")
        ContextMessageSecurityProvider.Context context = null
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments

        when:
        supportServiceAPI.generateSignRequest(
            context,
            "a864b33d-244a-4072-b540-0b29e2e7f40b",
            documents,
            "You want to sign?",
            user,
            "https://idp.cgi.com/v2/metadata",
            null,
            "https://localhost:8080/response",
            testProfile5,
            null,
            null
        )

        then:
        def e = thrown(ClientErrorException)
        e.message == "testProfile5.requestedCertAttributes.serialNumber.urn:oid:1.2.752.29.4.13 has no-integer order value."
    }

    @Unroll
    void "test generateSignRequest with invalid order value in the profileConfig"() {
        setup:
        User user = new User(userId: "190102030010")
        ContextMessageSecurityProvider.Context context = null
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments

        when:
        supportServiceAPI.generateSignRequest(
            context,"a864b33d-244a-4072-b540-0b29e2e7f40b",
            documents,
            "You want to sign?",
            user,
            "https://idp.cgi.com/v2/metadata",
            null,
            "https://localhost:8080/response",
            testProfile6,
            null,
            null
        )

        then:
        def e = thrown(ClientErrorException)
        e.message == "testProfile6.requestedCertAttributes.serialNumber.urn:oid:1.2.752.29.4.13 has invalid order value. Order must be larger than or equal to 0"
    }

    @Unroll
    void "test generateSignRequest with invalid attribute types in the profileConfig"() {
        setup:
        User user = new User(userId: "190102030010")
        ContextMessageSecurityProvider.Context context = null
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments

        when:
        supportServiceAPI.generateSignRequest(
            context,
            "a864b33d-244a-4072-b540-0b29e2e7f40b",
            documents,
            "You want to sign?",
            user,
            "https://idp.cgi.com/v2/metadata",
            null,
            "https://localhost:8080/response",
            testProfile7,
            null,
            null
        )

        then:
        def e = thrown(ClientErrorException)
        e.message == "The samlAttributeName under testProfile7.requestedCertAttributes must be a string or a list of map."
    }

    @Unroll
    void "test generateSignMessage with different mimeType"() {
        setup:
        SupportAPIProfile profile = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile1.yml")) as Map)
        ContextMessageSecurityProvider.Context context = new ContextMessageSecurityProvider.Context(Constants.CONTEXT_USAGE_SIGNREQUEST)
        when:
        profile.signMessageMimeType = "text"
        def signMessage = supportServiceAPI.generateSignMessage(
                context,
                "You want to sign?",
                "https://idp.cgi.com/v2/metadata",
                profile
        )
        then:
        signMessage.mimeType == "text"

        when:
        profile.signMessageMimeType = "MARKDOWN"
        signMessage = supportServiceAPI.generateSignMessage(
                context,
                "You want to sign?",
                "https://idp.cgi.com/v2/metadata",
                profile
        )
        then:
        signMessage.mimeType == "text/markdown"

        when:
        profile.signMessageMimeType = "html"
        signMessage = supportServiceAPI.generateSignMessage(
                context,
                "You want to sign?",
                "https://idp.cgi.com/v2/metadata",
                profile
        )
        then:
        signMessage.mimeType == "text/html"

        when:
        profile.signMessageMimeType = "invalid"
        signMessage = supportServiceAPI.generateSignMessage(
                context,
                "You want to sign?",
                "https://idp.cgi.com/v2/metadata",
                profile
        )
        then:
        signMessage.mimeType == "text"
    }

    def "test getNotBefore"() {
        when:
        GregorianCalendar requestTime = new GregorianCalendar()
        GregorianCalendar notBefore = supportServiceAPI.getNotBefore(requestTime, testProfile1)
        GregorianCalendar expectedNotBefore = requestTime
        expectedNotBefore.add(Calendar.MINUTE, -5)

        then:
        notBefore == expectedNotBefore
    }

    def "test getNotOnOrAfter"() {
        when:
        GregorianCalendar requestTime = new GregorianCalendar()
        GregorianCalendar notBefore = supportServiceAPI.getNotOnOrAfter(requestTime, testProfile1)
        GregorianCalendar expectedNotOnOrAfter = requestTime
        expectedNotOnOrAfter.add(Calendar.MINUTE, 10)

        then:
        notBefore == expectedNotOnOrAfter
    }

    def "test validateTransactionId"() {
        when:
        boolean result
        try {
            supportServiceAPI.validateTransactionId(transactionId)
            result = true
        } catch(Exception){
            result = false
        }

        then:
        result == expectedResult

        where:
        transactionId                               | expectedResult
        "hej"                                       | false
        "1234567890123456789012345678901"           | false
        null                                        | false
        "2e2dda27-36d4-48db-8738-a8323ab7d52d"      | true
        "123456789012345abcdefghijklmnopqrstuvwxyz" | true
    }

    def "test storeTransactionState"() {
        when:
        supportServiceAPI.storeTransactionState("123456", new TransactionState(transactionId: "123456"))
        TransactionState restoredState = supportServiceAPI.fetchTransactionState("123456")

        then:
        restoredState != null
        restoredState.transactionId == "123456"
    }

    def "test getAuthnContextClassRefs"() {
        when:
        List<String> accRefs = supportServiceAPI.getAuthnContextClassRefs(authServiceId, profile, overrideAuthnContextClassRefs)

        then:
        accRefs == expectedAccRefs

        where:
        profile       | authServiceId      | overrideAuthnContextClassRefs           | expectedAccRefs
        testProfile8  | "https://testidp1" | null                                    | ["Ref:B"]
        testProfile8  | "https://testidpX" | null                                    | ["Ref:A"]
        testProfile9  | "https://testidp1" | null                                    | ["Ref:D"]
        testProfile9  | "https://testidpX" | null                                    | ["Ref:A", "Ref:B", "Ref:C"]
        testProfile9  | "https://testidp2" | null                                    | ["Ref:D", "Ref:G"]
        testProfile10 | "https://testidp1" | null                                    | ["Ref:C", "Ref:D"]
        testProfile10 | "https://testidpX" | null                                    | ["Ref:A", "Ref:B"]
        testProfile10 | "https://testidp2" | null                                    | ["Ref:B"]
        testProfile10 | "https://testidpX" | ["Ref:S"]                               | ["Ref:S"]
        testProfile10 | "https://testidp2" | ["Ref:S", "Ref:T"]                      | ["Ref:S", "Ref:T"]
    }

    @Unroll
    void "test generateSignRequest with RSA and signatureAttributes for setCertRequestProperties"() {
        setup:
        User user = new User(userId: "190102030010")
        ContextMessageSecurityProvider.Context context = null
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments
        def signatureAttributes = null
        if (signatureAttributeValue) {
            signatureAttributes = [new Attribute(key: ATTRIBUTE_AUTH_CONTEXT_CLASS_REF, value: signatureAttributeValue)]
        }

        when:
        byte[] response = supportServiceAPI.generateSignRequest(
                context,
                "a864b33d-244a-4072-b540-0b29e2e7f40b",
                documents,
                "You want to sign?",
                user,
                authenticationServiceId,
                overrideAuthnContextClassRefs,
                "https://localhost:8080/response",
                testProfile9,
                signatureAttributes,
                null
        )

        then:
        response != null
        def signRequest = new XmlSlurper().parse(new ByteArrayInputStream(Base64.decode(response)))
        authnContextClassRefsResult.every { signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.AuthnContextClassRef*.text().contains(it) }

        where:
        authnContextClassRefsResult | signatureAttributeValue | authenticationServiceId                                                                 | overrideAuthnContextClassRefs
        ["Ref:D"]                   | null                    | "https://testidp1"                                                                      | null
        ["Ref:D", "Ref:G"]          | null                    | "https://testidp2"                                                                      | null
        ["Ref:D"]                   | "Ref:D"                 | "https://testidp2"                                                                      | null
        ["Ref:D"]                   | "Ref:D"                 | "https://testidp1"                                                                      | null
        ["Ref:B"]                   | "Ref:B"                 | "https://testidpX"    /*Receives from profile config defaultAuthnContextClassRef(s)*/   | null
        ["Ref:A", "Ref:B", "Ref:C"] | null                    | "https://testidpX"    /*Receives from profile config defaultAuthnContextClassRef(s)*/   | null
        ["Ref:B"]                   | "Ref:B"                 | "https://testidpX"                                                                      | ["Ref:A", "Ref:B"]
    }

    @Unroll
    def "test setCertRequestProperties method"() {
        setup:
        def signRequestExtensionType = supportServiceAPI.sweEid2ObjectFactory.createSignRequestExtensionType();
        def signatureAttributes = null
        if (signatureAttributeValue) {
            signatureAttributes = [new Attribute(key: ATTRIBUTE_AUTH_CONTEXT_CLASS_REF, value: signatureAttributeValue)]
        }
        when:
        supportServiceAPI.setCertRequestProperties(signRequestExtensionType, authenticationServiceId, testProfile9, signatureAttributes, overrideAuthnContextClassRefs)

        then:
        signRequestExtensionType.certRequestProperties.authnContextClassRef.containsAll(authnContextClassRefsResult)

        where:
        authnContextClassRefsResult | signatureAttributeValue | authenticationServiceId                                                                 | overrideAuthnContextClassRefs
        ["Ref:D"]                   | null                    | "https://testidp1"                                                                      | null
        ["Ref:D", "Ref:G"]          | null                    | "https://testidp2"                                                                      | null
        ["Ref:D"]                   | "Ref:D"                 | "https://testidp2"                                                                      | null
        ["Ref:D"]                   | "Ref:D"                 | "https://testidp1"                                                                      | null
        ["Ref:B"]                   | "Ref:B"                 | "https://testidpX"    /*Receives from profile config defaultAuthnContextClassRef(s)*/   | null
        ["Ref:A", "Ref:B", "Ref:C"] | null                    | "https://testidpX"    /*Receives from profile config defaultAuthnContextClassRef(s)*/   | null
        ["Ref:D"]                   | "Ref:D"                 | "https://testidp1"                                                                      | ["Ref:D"]
    }

    def "test setCertRequestProperties method when exception is thrown"() {
        setup:
        def signRequestExtensionType = supportServiceAPI.sweEid2ObjectFactory.createSignRequestExtensionType();

        when:
        supportServiceAPI.setCertRequestProperties(signRequestExtensionType, "https://testidp1", testProfile10, [new Attribute(key: ATTRIBUTE_AUTH_CONTEXT_CLASS_REF, value: "Ref:B")], overrideAuthnContextClassRefs)

        then:
        def error = thrown(ClientErrorException)
        error.code == "10024"
        error.message.contains("Value specified in Signature Request 'signatureAttributes' for attribute 'auth_context_class_ref: Ref:B' is not set under related Profile Configuration for existing request property list " +
                "AuthnContextClassRefs: [Ref:C, Ref:D] for authenticationServiceId: https://testidp1, nor set in AuthnContextClassRefs override " + overrideAuthnContextClassRefs)

        where:
        overrideAuthnContextClassRefs << [
                null,
                ["Ref:C", "Ref:D"]
        ]
    }

    def "test setCertRequestProperties with empty overrideAuthnContextClassRefs list, exception is thrown"() {
        setup:
        def signRequestExtensionType = supportServiceAPI.sweEid2ObjectFactory.createSignRequestExtensionType();

        when:
        supportServiceAPI.setCertRequestProperties(signRequestExtensionType, "https://testidp1", testProfile10,
                [new Attribute(key: ATTRIBUTE_AUTH_CONTEXT_CLASS_REF, value: "Ref:B")], [])

        then:
        def error = thrown(ClientErrorException)
        error.code == "10026"
        error.message.contains("If a authnContextClassRefs list is supplied to override the profile settings, it must be non-empty")
    }

    def "test setVisibleSignature with all kinds of invalid attributes"(){
        setup:
        PAdESSignatureParameters parameters = new PAdESSignatureParameters()

        when:
        Attribute attribute = new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: "")
        supportServiceAPI.setVisibleSignature(testProfile1, parameters, "someSigner", "11223344", [attribute])
        then:
        def e = thrown(Exception)
        e.message == "Invalid sign attribute configured. Can't set visible_signature_position_x with empty value or null."

        when:
        attribute = new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: null)
        supportServiceAPI.setVisibleSignature(testProfile1, parameters, "someSigner","11223344", [attribute])
        then:
        e = thrown(Exception)
        e.message == "Invalid sign attribute configured. Can't set visible_signature_position_x with empty value or null."

        when:
        Attribute attribute1 = new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: "one")
        supportServiceAPI.setVisibleSignature(testProfile1, parameters, "someSigner", "11223344", [attribute1])
        then:
        def e1 = thrown(Exception)
        e1.message == "Invalid sign attribute visible_signature_position_x=one configured. Can't convert one to float value."

        when:
        Attribute attribute2 = new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: "-1")
        supportServiceAPI.setVisibleSignature(testProfile1, parameters, "someSigner", "11223344", [attribute2])
        then:
        def e2 = thrown(Exception)
        e2.message == "Make sure attribute: visible_signature_position_x is configured with a value equal or larger than 0."

        when:
        Attribute att_x = new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: "1")
        Attribute att_y = new Attribute(key: VISIBLE_SIGNATURE_POSITION_Y, value: "1")
        Attribute att_width = new Attribute(key: VISIBLE_SIGNATURE_WIDTH, value: "200")
        Attribute attribute5 = new Attribute(key: VISIBLE_SIGNATURE_HEIGHT, value: "10")
        supportServiceAPI.setVisibleSignature(testProfile1, parameters, "someSigner", "11223344", [att_x, att_y, att_width, attribute5])
        then:
        def e5 = thrown(Exception)
        e5.message == "Make sure attribute: visible_signature_height is configured with a value larger than 40. The minimum image size is: 180*40."

        when:
        Attribute attribute6 = new Attribute(key: VISIBLE_SIGNATURE_WIDTH, value: "10")
        supportServiceAPI.setVisibleSignature(testProfile1, parameters, "someSigner", "11223344", [att_x, att_y, attribute6])
        then:
        def e6 = thrown(Exception)
        e6.message == "Make sure attribute: visible_signature_width is configured with a value larger than 180. The minimum image size is: 180*40."
    }

    def "test setVisibleSignature with valid attributes input"(){
        setup:
        PAdESSignatureParameters parameters = new PAdESSignatureParameters()

        when:
        def attributes = [new Attribute(key: VISIBLE_SIGNATURE_PAGE, value: "1"),
                          new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: "20"),
                          new Attribute(key: VISIBLE_SIGNATURE_POSITION_Y, value: "30"),
                          new Attribute(key: VISIBLE_SIGNATURE_WIDTH, value: "200"),
                          new Attribute(key: VISIBLE_SIGNATURE_HEIGHT, value: "50")]
        supportServiceAPI.setVisibleSignature(testProfile1, parameters, "someSigner", "11223344", attributes)
        then:
        parameters.imageParameters.fieldParameters.page == 1
        parameters.imageParameters.fieldParameters.originX == 20
        parameters.imageParameters.fieldParameters.originY == 30
        parameters.imageParameters.fieldParameters.width == 200
        parameters.imageParameters.fieldParameters.height == 50
        parameters.imageParameters.image != null
    }

    def "test setVisibleSignature with valid attributes from caches"(){
        setup:
        PAdESSignatureParameters parameters = new PAdESSignatureParameters()
        DateFormat dateFormat = new SimpleDateFormat(testProfile1.visibleSignature.timeStampFormat)

        when:
        supportServiceAPI.cacheProvider.set("11223344", VISIBLE_SIGNATURE_PAGE, "1")
        supportServiceAPI.cacheProvider.set("11223344", VISIBLE_SIGNATURE_POSITION_X, "20")
        supportServiceAPI.cacheProvider.set("11223344", VISIBLE_SIGNATURE_POSITION_Y, "30")
        supportServiceAPI.cacheProvider.set("11223344", VISIBLE_SIGNATURE_WIDTH, "40")
        supportServiceAPI.cacheProvider.set("11223344", VISIBLE_SIGNATURE_HEIGHT, "50")
        supportServiceAPI.setVisibleSignature(testProfile1, parameters, "someSigner", "11223344", null)
        then:
        parameters.imageParameters.fieldParameters.page == 1
        parameters.imageParameters.fieldParameters.originX == 20
        parameters.imageParameters.fieldParameters.originY == 30
        parameters.imageParameters.fieldParameters.width == 40
        parameters.imageParameters.fieldParameters.height == 50
        parameters.imageParameters.textParameters.text == "Document Digital Signed\nSigner: someSigner\nTime: ${dateFormat.format(parameters.bLevel().signingDate)}"
    }

    def "test setVisibleSignature with valid attributes input but invalid image resource"(){
        setup:
        PAdESSignatureParameters parameters = new PAdESSignatureParameters()

        when:
        def attributes = [new Attribute(key: VISIBLE_SIGNATURE_PAGE, value: "1"),
                          new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: "20"),
                          new Attribute(key: VISIBLE_SIGNATURE_POSITION_Y, value: "30"),
                          new Attribute(key: VISIBLE_SIGNATURE_WIDTH, value: "200"),
                          new Attribute(key: VISIBLE_SIGNATURE_HEIGHT, value: "50")]
        supportServiceAPI.setVisibleSignature(testProfile1, parameters, "someSigner", "11223344", attributes)
        then:
        parameters.imageParameters.fieldParameters.page == 1
        parameters.imageParameters.fieldParameters.originX == 20
        parameters.imageParameters.fieldParameters.originY == 30
        parameters.imageParameters.fieldParameters.width == 200
        parameters.imageParameters.fieldParameters.height == 50
        parameters.imageParameters.image != null
    }

    void "test setVisibleSignature with signature text template"(){
        setup:
        DateFormat dateFormat
        SupportAPIProfile profile = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile1.yml")) as Map)
        PAdESSignatureParameters parameters = new PAdESSignatureParameters()
        def attributes = [new Attribute(key: VISIBLE_SIGNATURE_PAGE, value: "1"),
                          new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: "20"),
                          new Attribute(key: VISIBLE_SIGNATURE_POSITION_Y, value: "30"),
                          new Attribute(key: VISIBLE_SIGNATURE_WIDTH, value: "200"),
                          new Attribute(key: VISIBLE_SIGNATURE_HEIGHT, value: "50")]
        dateFormat = new SimpleDateFormat(profile.visibleSignature.timeStampFormat)

        when:
        profile.visibleSignature.signatureTextTemplate = "Document has been signed\nSigner name: {signerName}\nTime: {timestamp}"
        supportServiceAPI.setVisibleSignature(profile, parameters, "someSigner", "11223344", attributes)

        then:
        parameters.imageParameters.textParameters.text == "Document has been signed\nSigner name: someSigner\nTime: ${dateFormat.format(parameters.bLevel().signingDate)}"

        when:
        profile.visibleSignature.signatureTextTemplate = "Signed document"
        supportServiceAPI.setVisibleSignature(profile, parameters, "someSigner", "22334455", attributes)

        then:
        parameters.imageParameters.textParameters.text == "Signed document"

        when:
        profile.visibleSignature.timeStampFormat = "yyyy-MM-dd"
        dateFormat = new SimpleDateFormat(profile.visibleSignature.timeStampFormat)
        profile.visibleSignature.signatureTextTemplate = "Document signed by:\n{signerName} @ {timestamp}"
        supportServiceAPI.setVisibleSignature(profile, parameters, "someSigner", "33445566", attributes)

        then:
        parameters.imageParameters.textParameters.text == "Document signed by:\nsomeSigner @ ${dateFormat.format(parameters.bLevel().signingDate)}"

        when:
        attributes.add(new Attribute(key: "customName", value: "Johnny Cash"))
        attributes.add(new Attribute(key: "department", value: "Men in black"))
        profile.visibleSignature.signatureTextTemplate = "Signed by: {signatureAttribute.customName}\nDepartment: {signatureAttribute.department}"
        supportServiceAPI.setVisibleSignature(profile, parameters, "someSigner", "44556677", attributes)

        then:
        parameters.imageParameters.textParameters.text == "Signed by: Johnny Cash\nDepartment: Men in black"
    }

    def "test to specify logo image as signature parameter"() {
        setup:
        SupportAPIProfile profile = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile1.yml")) as Map)
        PAdESSignatureParameters parameters = new PAdESSignatureParameters()
        byte[] imageData = new File("src/test/resources/testlogo.png").bytes
        def attributes = [new Attribute(key: VISIBLE_SIGNATURE_LOGO_IMAGE, value: new String(Base64.encode(imageData)))]

        when:
        supportServiceAPI.setVisibleSignature(profile, parameters, "someSigner", "99887766", attributes)
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream()
        parameters.imageParameters.image.writeTo(outputStream)

        then:
        outputStream.toByteArray() == imageData
    }

    def "test to specify signature attributes per document"(){
        setup:
        SupportAPIProfile profile = new SupportAPIProfile.Builder()
            .relatedProfile("testProfile")
            .addTrustedAuthenticationService("authService", "authService", "authService")
            .addRequestedCertAttribute("certAttribute", "certAttribute", "certAttribute", false)
            .addAuthorizedConsumerURL("consumerUrl")
            .visibleSignatureConfig(new VisibleSignatureConfig(
                    ["enable": "true"]
            ))
            .build()
        DocumentRequests documentRequests = new DocumentRequests([
            new DocumentSigningRequest(referenceId: "1", data: new File("src/test/resources/testdocument.pdf").bytes, type: "application/pdf", name: "testdocument1.pdf"),
            new DocumentSigningRequest(referenceId: "2", data: new File("src/test/resources/testdocument.pdf").bytes, type: "application/pdf", name: "testdocument2.pdf"),
            new DocumentSigningRequest(referenceId: "3", data: new File("src/test/resources/testdocument.pdf").bytes, type: "application/pdf", name: "testdocument3.pdf")
        ])
        User user = new User(userId: "190101010001")
        List<Attribute> signatureAttributes = []
        Map<String,List<Attribute>> documentSignatureAttributes = [
                "1": [
                        new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: 10),
                        new Attribute(key: VISIBLE_SIGNATURE_POSITION_Y, value: 10)
                ],
                "2": [
                        new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: 20),
                        new Attribute(key: VISIBLE_SIGNATURE_POSITION_Y, value: 20)
                ],
                "3": [
                        new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: 30),
                        new Attribute(key: VISIBLE_SIGNATURE_POSITION_Y, value: 30)
                ]
        ]
        V2SupportServiceAPI supportServiceAPISpy = Spy(supportServiceAPI)
        String transactionId = UUID.randomUUID().toString()
        String strongReferenceId1 = SupportLibraryUtils.generateStrongReferenceId(transactionId, "1")
        String strongReferenceId2 = SupportLibraryUtils.generateStrongReferenceId(transactionId, "2")
        String strongReferenceId3 = SupportLibraryUtils.generateStrongReferenceId(transactionId, "3")
        List<String> verifiedContextIds = []

        when:
        PreparedSignatureResponse response = supportServiceAPISpy.prepareSignature(profile, documentRequests, transactionId,
                "Test signature attributes", user, "authService", "consumerUrl",
                signatureAttributes, documentSignatureAttributes
        )

        then:
        response != null
        3 * supportServiceAPISpy.setVisibleSignature(_,_,_,_,_,) >> { SupportAPIProfile config, PAdESSignatureParameters parameters, String signerName, String contextId, List<Attribute> attributes ->
            assert signerName == "190101010001"

            if(contextId == strongReferenceId1){
                assert attributes.find { it.key == VISIBLE_SIGNATURE_POSITION_X }?.value == "10"
                assert attributes.find { it.key == VISIBLE_SIGNATURE_POSITION_Y }?.value == "10"
            }

            if(contextId == strongReferenceId2){
                assert attributes.find { it.key == VISIBLE_SIGNATURE_POSITION_X }?.value == "20"
                assert attributes.find { it.key == VISIBLE_SIGNATURE_POSITION_Y }?.value == "20"
            }

            if(contextId == strongReferenceId3){
                assert attributes.find { it.key == VISIBLE_SIGNATURE_POSITION_X }?.value == "30"
                assert attributes.find { it.key == VISIBLE_SIGNATURE_POSITION_Y }?.value == "30"
            }

            // Verify 3 unique context IDs were used.
            assert !verifiedContextIds.contains(contextId)
            verifiedContextIds.add(contextId)
        }
    }

    def "test that unsupported document signature attributes result in error"(){
        setup:
        SupportAPIProfile profile = new SupportAPIProfile.Builder()
                .relatedProfile("testProfile")
                .addTrustedAuthenticationService("authService", "authService", "authService")
                .addRequestedCertAttribute("certAttribute", "certAttribute", "certAttribute", false)
                .addAuthorizedConsumerURL("consumerUrl")
                .visibleSignatureConfig(new VisibleSignatureConfig(
                        ["enable": "true"]
                ))
                .build()
        DocumentRequests documentRequests = new DocumentRequests([
                new DocumentSigningRequest(referenceId: "abc123", data: new File("src/test/resources/testdocument.pdf").bytes, type: "application/pdf", name: "testdocument1.pdf"),
        ])
        User user = new User(userId: "190101010001")
        List<Attribute> signatureAttributes = []
        Map<String,List<Attribute>> documentSignatureAttributes = [
                "abc123": [
                        new Attribute(key: ATTRIBUTE_AUTH_CONTEXT_CLASS_REF, value: "classRef42"),
                ]
        ]

        when:
        supportServiceAPI.prepareSignature(profile, documentRequests, UUID.randomUUID().toString(),
                "Test signature attributes", user, "authService", "consumerUrl",
                signatureAttributes, documentSignatureAttributes
        )

        then:
        ClientErrorException exception = thrown()
        exception.message == "The provided signature attribute (auth_context_class_ref) is not allowed to be specified per document"
    }

    def "test that signature attribute pre-processor is called for all documents"(){
        setup:
        User user = new User(userId: "190102030010")
        ContextMessageSecurityProvider.Context context = null
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments
        List<Attribute> signatureAttributes = [
                new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: "50"),
                new Attribute(key: VISIBLE_SIGNATURE_POSITION_Y, value: "50"),
                new Attribute(key: VISIBLE_SIGNATURE_PAGE, value: "1")
        ]
        def signatureAttributePreProcessorMock = Mock(SignatureAttributePreProcessor)
        supportServiceAPI.signatureAttributePreProcessors[SigType.XML] = signatureAttributePreProcessorMock
        supportServiceAPI.signatureAttributePreProcessors[SigType.PDF] = signatureAttributePreProcessorMock
        supportServiceAPI.signatureAttributePreProcessors[SigType.CMS] = signatureAttributePreProcessorMock

        when:
        byte[] response = supportServiceAPI.generateSignRequest(
                context,
                "28717ddd-4166-4f52-b8ea-f9f50bcf46e0",
                documents,
                "You want to sign?",
                user,
                "https://idp.cgi.com/v2/metadata",
                null,
                "https://localhost:8080/response",
                testProfile1,
                signatureAttributes,
                null
        )

        then:
        response != null
        3 * signatureAttributePreProcessorMock.preProcess(_, _) >> {List<Attribute> attributes, DocumentSigningRequest document ->
            assert attributes.containsAll(signatureAttributes)
            assert document != null
            assert testDocuments.contains(document)
        }
    }

    @Unroll
    def "Test verifyDocument on #documentType document"() {
        when:
        VerifyDocumentResponse response = supportServiceAPI.verifyDocument(testProfile1, testDocument)
        println new String(response.reportData)
        def xmlReport = new XmlSlurper().parseText(new String(response.reportData))
        X509Certificate signingCertificate = CertUtils.getX509CertificateFromPEMorDER(response.signatures.signer.first().signerCertificate)

        then:
        response.verifies
        xmlReport.Signature[0].@SignatureFormat == expectedSignatureFormat
        response.reportData != null
        response.reportMimeType == "text/xml"
        response.referenceId == testDocument.referenceId
        response.signatures != null
        response.signatures.signer != null
        response.signatures.signer.size() == 1
        response.signatures.signer.get(0).levelOfAssurance == "http://id.elegnamnden.se/loa/1.0/loa3"
        response.signatures.signer.get(0).signerId == expectedSignerId
        response.signatures.signer.get(0).issuerId == "CN=sub Network - Development"
        response.signatures.signer.get(0).signingAlgorithm == expectedSigningAlgorithm
        response.signatures.signer.get(0).signingDate.after(signingCertificate.notBefore)
        response.signatures.signer.get(0).signingDate.before(signingCertificate.notAfter)
        response.signatures.signer.get(0).validFrom == signingCertificate.notBefore
        response.signatures.signer.get(0).validTo == signingCertificate.notAfter

        where:
        testDocument            | documentType | expectedSignatureFormat | expectedSignerId     | expectedSigningAlgorithm
        testSignedXMLDocument   | "XML"        | "XAdES-BASELINE-B"      | "PNOSE-195207092072" | "SHA256withRSAandMGF1"
        testSignedPDFDocument   | "PDF"        | "PAdES-BASELINE-B"      | "195207092072"       | "SHA256withRSA"
        testSignedCMSDocument   | "CMS"        | "CAdES-BASELINE-B"      | "195207092072"       | "SHA256withRSA"
    }

    @Unroll
    def "Test verifyDocument on unsigned #documentType document"() {
        when:
        VerifyDocumentResponse response = supportServiceAPI.verifyDocument(testProfile1, testDocument)

        then:
        !response.verifies
        response.signatures.signer.size() == 0
        response.reportData == null
        response.referenceId == testDocument.referenceId

        where:
        testDocument            | documentType
        testUnsignedXMLDocument | "XML"
        testUnsignedPDFDocument | "PDF"
        testUnsignedCMSDocument | "CMS"
    }

    def "Test verifyDocument signed with XML DSig"() {
        when:
        VerifyDocumentResponse response = supportServiceAPI.verifyDocument(testProfile1, testSignedXMLNonETSIDocument)
        println new String(response.reportData)
        def xmlReport = new XmlSlurper().parseText(new String(response.reportData))
        X509Certificate signingCertificate = CertUtils.getX509CertificateFromPEMorDER(response.signatures.signer.first().signerCertificate)

        then:
        response.verifies
        xmlReport.Signature[0].@SignatureFormat == "XML-NOT-ETSI"
        response.reportMimeType == "text/xml"
        signingCertificate != null
        response.referenceId == testSignedXMLNonETSIDocument.referenceId
        response.signatures.signer.get(0).issuerId == "CN=RSA Signer,O=Certificate Services,L=Kista,ST=Stockholm,C=SE"
        response.signatures.signer.get(0).signingAlgorithm == "SHA256withRSA"
        response.signatures.signer.get(0).validFrom == signingCertificate.notBefore
        response.signatures.signer.get(0).validTo == signingCertificate.notAfter
        response.signatures.signer.get(0).levelOfAssurance == null
        response.signatures.signer.get(0).signerId == null
        response.signatures.signer.get(0).signerDisplayName == null
        response.signatures.signer.get(0).signingDate == null
    }

    def "Test verifyDocument modified XML"() {
        setup:
        byte[] originalData = testSignedXMLDocument.data

        when:
        testSignedXMLDocument.data = new String (originalData, "UTF-8").replaceAll("Heisenberg", "Heisenburg").getBytes("UTF-8")
        VerifyDocumentResponse response = supportServiceAPI.verifyDocument(testProfile1, testSignedXMLDocument)
        println new String(response.reportData)

        then:
        !response.verifies

        cleanup:
        testSignedXMLDocument.data = originalData
    }

    def "test that proxy settings are not used if not specified"(){
        when:
        ProxyConfig crlProxyConfig = ((CommonsDataLoader)((FileCacheDataLoader)((OnlineCRLSource)supportServiceAPI.certificateVerifier.crlSource).dataLoader).dataLoader).proxyConfig
        ProxyConfig ocspProxyConfig = ((CommonsDataLoader)((OCSPDataLoader)((OnlineOCSPSource)supportServiceAPI.certificateVerifier.ocspSource).dataLoader)).proxyConfig

        then:
        crlProxyConfig == null
        ocspProxyConfig == null
    }

    def "test that proxy settings are used if specified"(){
        when:
        V2SupportServiceAPI proxyAPI = new V2SupportServiceAPI.Builder()
            .messageSecurityProvider(Mock(MessageSecurityProvider))
            .validationProxy("proxy.test.com", 1234, "user", "pass", ["google.com", "ikea.se"])
            .build() as V2SupportServiceAPI
        ProxyConfig crlProxyConfig = ((CommonsDataLoader)((FileCacheDataLoader)((OnlineCRLSource)proxyAPI.certificateVerifier.crlSource).dataLoader).dataLoader).proxyConfig
        ProxyConfig ocspProxyConfig = ((CommonsDataLoader)((OCSPDataLoader)((OnlineOCSPSource)proxyAPI.certificateVerifier.ocspSource).dataLoader)).proxyConfig

        then:
        crlProxyConfig != null
        crlProxyConfig.httpsProperties.host == "proxy.test.com"
        crlProxyConfig.httpsProperties.port == 1234
        crlProxyConfig.httpsProperties.user == "user"
        crlProxyConfig.httpsProperties.password == "pass".toCharArray()
        crlProxyConfig.httpsProperties.excludedHosts.containsAll(["google.com", "ikea.se"])
        crlProxyConfig.httpProperties.host == "proxy.test.com"
        crlProxyConfig.httpProperties.port == 1234
        crlProxyConfig.httpProperties.user == "user"
        crlProxyConfig.httpProperties.password == "pass".toCharArray()
        crlProxyConfig.httpProperties.excludedHosts.containsAll(["google.com", "ikea.se"])
        ocspProxyConfig != null
        ocspProxyConfig.httpsProperties.host == "proxy.test.com"
        ocspProxyConfig.httpsProperties.port == 1234
        ocspProxyConfig.httpsProperties.user == "user"
        ocspProxyConfig.httpsProperties.password == "pass".toCharArray()
        ocspProxyConfig.httpsProperties.excludedHosts.containsAll(["google.com", "ikea.se"])
        ocspProxyConfig.httpProperties.host == "proxy.test.com"
        ocspProxyConfig.httpProperties.port == 1234
        ocspProxyConfig.httpProperties.user == "user"
        ocspProxyConfig.httpProperties.password == "pass".toCharArray()
        ocspProxyConfig.httpProperties.excludedHosts.containsAll(["google.com", "ikea.se"])
    }

    @Unroll
    def "test that getSignServiceRequestURL returns correct"() {
        setup:
        SupportAPIProfile profile = Mock(SupportAPIProfile)
        profile.getSignServiceRequestURL() >> "https://signservice.test.se/"

        when:
        def result = supportServiceAPI.getSignServiceRequestURL(profile, signatureAttributes)

        then:
        result == expectedUrl

        where:
        expectedUrl                                      | signatureAttributes
        "https://signservice.test.se/"                   | null
        "https://signservice.signatureattributetest.se/" | [new Attribute(key: ATTRIBUTE_SIGNSERVICE_REQUEST_URL, value: "https://signservice.signatureattributetest.se/")]
    }

    def "test generateSignRequest with LTA profile"(){
        setup:
        User user = new User(userId: "190102030010")
        ContextMessageSecurityProvider.Context context = null
        DocumentRequests documents = new DocumentRequests()
        documents.documents = testDocuments

        when:
        byte[] response = supportServiceAPI.generateSignRequest(
                context,
                "a864b33d-244a-4072-b540-0b29e2e7f30a",
                documents,
                "You want to sign?",
                user,
                "https://idp.cgi.com/v2/metadata",
                null,
                "https://localhost:8080/response",
                testProfile11,
                null,
                null
        )

        then:
        response != null
        supportServiceAPI.onlineTSPSources.get("http://timestamp.digicert.com") != null
        println new String(Base64.decode(response), "UTF-8")
    }

    def "test completeSignature with unsuccessful sign response"(){
        setup:
        supportServiceAPI.sweEID2DSSExtensionsMessageParser = Mock(SweEID2DSSExtensionsMessageParser)
        def supportServiceAPISpy = Spy(supportServiceAPI)
        supportServiceAPISpy.fetchTransactionState(_) >> Mock(TransactionState)
        supportServiceAPI.sweEID2DSSExtensionsMessageParser.parseMessage(_, _, _) >> new SignResponse(result: new Result(resultMajor: "urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError"))
        def exception

        when:
        try {
            supportServiceAPISpy.completeSignature(
                    new SupportAPIProfile(),
                    "c2lnblJlc3BvbnNl",
                    "123456"
            )
        } catch (ServerErrorException e) {
            exception = e
        }

        then:
        exception != null
        exception.code == "10012"
        exception.detailMessage == "Sign response failed with error message: No detailed error message available. It's possible the authentication was canceled by the user."
    }

    static int getMinutesBetween(String a, String b) {
        OffsetDateTime aDate = OffsetDateTime.parse(a as String, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
        OffsetDateTime bDate = OffsetDateTime.parse(b as String, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
        Duration duration = Duration.between(aDate, bDate)
        return Math.abs(duration.toMinutes())
    }

    static int getMinutesBetween(String a, Date b) {
        OffsetDateTime aDate = OffsetDateTime.parse(a as String, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
        def bInstant = b.toInstant()
        ZonedDateTime bDate = ZonedDateTime.ofInstant(bInstant, ZoneId.systemDefault())
        Duration duration = Duration.between(aDate, bDate)
        return Math.abs(duration.toMinutes())
    }

    static SupportAPIProfile getProfile(Map profileData){
        ObjectMapper objectMapper = new ObjectMapper()
        return objectMapper.convertValue(profileData, SupportAPIProfile.class)
    }
}
