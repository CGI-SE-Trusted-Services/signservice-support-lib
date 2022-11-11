package se.signatureservice.support.api.v2

import com.fasterxml.jackson.databind.ObjectMapper
import groovy.xml.XmlSlurper
import groovy.yaml.YamlSlurper
import org.bouncycastle.util.encoders.Base64
import org.certificateservices.messages.ContextMessageSecurityProvider
import org.certificateservices.messages.utils.CertUtils
import org.joda.time.DateTime
import org.joda.time.DateTimeZone
import org.joda.time.Minutes
import org.joda.time.format.DateTimeFormatter
import org.joda.time.format.ISODateTimeFormat
import se.signatureservice.configuration.support.system.Constants
import se.signatureservice.support.common.cache.SimpleCacheProvider
import se.signatureservice.support.system.SupportAPIProfile
import se.signatureservice.support.utils.SupportLibraryUtils
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import java.security.cert.X509Certificate

class V2SupportServiceAPISpec extends Specification {
    @Shared V2SupportServiceAPI supportServiceAPI
    @Shared List<Object> testDocuments = []

    static YamlSlurper yamlSlurper = new YamlSlurper()

    static SupportAPIProfile testProfile1 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile1.yml")) as Map)
    static SupportAPIProfile testProfile2 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile2.yml")) as Map)
    static SupportAPIProfile testProfile3 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile3.yml")) as Map)

    static X509Certificate testRecipientCert

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
            .build() as V2SupportServiceAPI

        testDocuments.add(new DocumentSigningRequest(referenceId: "123456", type: "application/pdf", name: "testdocument.pdf", data: new File("src/test/resources/testdocument.pdf").bytes))
        testDocuments.add(new DocumentSigningRequest(referenceId: "234567", type: "text/xml", name: "testdocument.xml", data: new File("src/test/resources/testdocument.xml").bytes))
        testDocuments.add(new DocumentSigningRequest(referenceId: "345678", type: "application/octet-stream", name: "testdocument.doc", data: new File("src/test/resources/testdocument.doc").bytes))
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
                "https://localhost:8080/response",
                testProfile1,
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
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.AuthnContextClassRef == "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"
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
                "https://localhost:8080/response",
                testProfile2,
                null
        )

        then:
        response != null
        println new String(Base64.decode(response), "UTF-8")

        def signRequest = new groovy.util.XmlSlurper().parse(new ByteArrayInputStream(Base64.decode(response)))
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
        signRequest.OptionalInputs.SignRequestExtension.CertRequestProperties.AuthnContextClassRef == "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
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
        def signedInfo = new groovy.util.XmlSlurper().parseText(new String(Base64.decode((signRequest.InputDocuments.Other.SignTasks.SignTaskData.find{it.@SigType=="XML"}.ToBeSignedBytes as String).bytes)))
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
                "https://localhost:8080/response",
                testProfile3,
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

    static int getMinutesBetween(String a, String b) {
        DateTimeFormatter timeFormater = ISODateTimeFormat.dateTime().withZone(DateTimeZone.getDefault())
        def aDate = timeFormater.parseDateTime(a as String)
        def bDate = timeFormater.parseDateTime(b as String)
        return Minutes.minutesBetween(aDate, bDate).minutes
    }

    static int getMinutesBetween(String a, Date b) {
        DateTimeFormatter timeFormater = ISODateTimeFormat.dateTime().withZone(DateTimeZone.getDefault())
        def aDate = timeFormater.parseDateTime(a as String)
        def bDate = new DateTime(b)
        return Minutes.minutesBetween(aDate, bDate).minutes
    }

    static SupportAPIProfile getProfile(Map profileData){
        ObjectMapper objectMapper = new ObjectMapper()
        return objectMapper.convertValue(profileData, SupportAPIProfile.class)
    }
}
