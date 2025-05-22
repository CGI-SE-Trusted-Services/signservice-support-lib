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

import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import groovy.xml.XmlSlurper
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import se.signatureservice.messages.MessageSecurityProvider
import se.signatureservice.support.api.SupportServiceAPI
import se.signatureservice.support.common.cache.SimpleCacheProvider
import se.signatureservice.support.system.SupportAPIProfile
import se.signatureservice.support.utils.SupportLibraryUtils
import spock.lang.Ignore
import spock.lang.Specification

import javax.xml.parsers.SAXParserFactory

/**
 * Special test that should be run manually with a dummy-idp and related systems up and running.
 *
 * Test used in order to verify the API. Requires that the following services are started
 *  - eid2-dummy-idp
 *  - signservice-frontend
 *  - signservice-backend
 */
@Ignore
class V2SupportServiceAPIIntegrationSpec extends Specification  {
    static MessageSecurityProvider messageSecurityProvider
    static SupportServiceAPI supportServiceAPI
    static SupportAPIProfile profileConfig

    def setupSpec(){
        // Create a message security provider that will be used when signing
        // requests and when verifying responses.
        messageSecurityProvider = SupportLibraryUtils.createSimpleMessageSecurityProvider(
                "src/test/resources/keystore.jks",
                "TSWCeC",
                "8af76eae8e1a201;cn=mock issuing ca,o=mockasiner ab,c=se",
                "src/test/resources/truststore.jks",
                "foo123"
        )

        // Build an instance of the support service API with the newly created
        // security provider. We are using a simple cache provider that stores
        // everything in-memory.
        supportServiceAPI = new V2SupportServiceAPI.Builder()
                .messageSecurityProvider(messageSecurityProvider)
                .cacheProvider(new SimpleCacheProvider())
                .trustedCertificateSource(new KeyStoreCertificateSource("src/test/resources/validation-truststore.jks", "JKS", "foo123".toCharArray()))
                .build()

        // Create profile configuration to use for the transaction. This can be re-used if needed.
        profileConfig = new SupportAPIProfile.Builder()
                .signServiceId("http://localhost:8080/signservice-frontend/metadata/1834c194136")
                .signServiceRequestURL("http://localhost:8080/signservice-frontend/request/1834c194136")
                .addTrustedAuthenticationService("Dummy idP", "http://localhost:6060/eid2-dummy-idp/samlv2/idp/metadata", "Signature Service Dummy iDP")
                .addRequestedCertAttribute("givenName",  "urn:oid:2.5.4.42", "2.5.4.42", true)
                .addRequestedCertAttribute("sn", "urn:oid:2.5.4.4", "2.5.4.4", true)
                .addRequestedCertAttribute("serialNumber", "urn:oid:1.2.752.29.4.13", "2.5.4.5", true)
                .addRequestedCertAttribute("commonName", "urn:oid:2.16.840.1.113730.3.1.241", "2.5.4.3", false)
                .addRequestedCertAttribute("displayName", "urn:oid:2.16.840.1.113730.3.1.241", "2.16.840.1.113730.3.1.241", false)
                .addRequestedCertAttribute("c", "urn:oid:2.5.4.6", "2.5.4.6", false)
                .addRequestedCertAttribute("gender", "urn:oid:1.3.6.1.5.5.7.9.3", "1.3.6.1.5.5.7.9.3", "sda", false)
                .addAuthorizedConsumerURL("http://localhost")
                .signRequester("http://localhost:9090/signservice-support/metadata")
                .signatureAlgorithm("SHA256withRSA")
                .relatedProfile("rsaProfile")
                .enableAuthnProfile(true)
                .build()
    }

    def cleanupSpec(){
    }

    def "perform XML document signing and verification"(){
        when:

        // Create user that is going to sign the document(s)
        User user = new User.Builder()
                .userId("195207092072")
                .role("testrole")
                .build()

        // Create document requests to include in the transaction.
        DocumentRequests documentRequests = new DocumentRequests.Builder()
                .addXMLDocument("../signservice-support/src/test/resources/testdocument.xml")
                .build()

        // Generate the prepared signature request using the support service API.
        PreparedSignatureResponse preparedSignature = supportServiceAPI.prepareSignature(
                profileConfig,
                documentRequests,
                null,
                "Im signing everything",
                user,
                "http://localhost:6060/eid2-dummy-idp/samlv2/idp/metadata",
                "http://localhost",
                null
        )

        // Send the signature request to central system to receive SAML request.
        Map<String,String> response = processSignRequest(preparedSignature.signRequest, preparedSignature.actionURL)

        // Send SAML request to identity provider to receive the SAML response.
        response = processAuthnRequest(response["SAMLRequest"] as String, response["RelayState"] as String, response["ActionURL"] as String, user.userId)

        // Send SAML response to central system to receive the sign response.
        response = processAuthnResponse(response["SAMLResponse"] as String, response["RelayState"] as String, response["ActionURL"] as String)

        // Process the sign response using the support service API in order to get the complete signed document.
        CompleteSignatureResponse completeSignature = supportServiceAPI.completeSignature(
                profileConfig,
                response["EidSignResponse"] as String,
                preparedSignature.transactionId
        )

        Document signedDocument = completeSignature.documents.documents.first() as Document
        assert signedDocument != null
        new File("build/tmp/signed_${signedDocument.name}").bytes = signedDocument.data

        VerifyDocumentResponse verifiedDocument = supportServiceAPI.verifyDocument(profileConfig, signedDocument);

        then:
        verifiedDocument != null

        println "-----BEGIN VALIDATION REPORT-----"
        println new String(verifiedDocument.reportData)
        println "-----END VALIDATION REPORT-----"
        verifiedDocument.isVerifies()
    }

    def "perform PDF document signing and verification"(){
        when:
        // Create user that is going to sign the document(s)
        User user = new User.Builder()
                .userId("195207092072")
                .role("testrole")
                .build()

        // Create document requests to include in the transaction.
        DocumentRequests documentRequests = new DocumentRequests.Builder()
                .addPDFDocument("src/test/resources/testdocument.pdf")
                .build()

        // Generate the prepared signature request using the support service API.
        PreparedSignatureResponse preparedSignature = supportServiceAPI.prepareSignature(
                profileConfig,
                documentRequests,
                null,
                "Im signing everything",
                user,
                "http://localhost:6060/eid2-dummy-idp/samlv2/idp/metadata",
                "http://localhost",
                null
        )

        // Send the signature request to central system to receive SAML request.
        Map<String,String> response = processSignRequest(preparedSignature.signRequest, preparedSignature.actionURL)

        // Send SAML request to identity provider to receive the SAML response.
        response = processAuthnRequest(response["SAMLRequest"] as String, response["RelayState"] as String, response["ActionURL"] as String, user.userId)

        // Send SAML response to central system to receive the sign response.
        response = processAuthnResponse(response["SAMLResponse"] as String, response["RelayState"] as String, response["ActionURL"] as String)

        // Process the sign response using the support service API in order to get the complete signed document.
        CompleteSignatureResponse completeSignature = supportServiceAPI.completeSignature(
                profileConfig,
                response["EidSignResponse"] as String,
                preparedSignature.transactionId
        )

        Document signedDocument = completeSignature.documents.documents.first() as Document
        new File("build/tmp/signed_${signedDocument.name}").bytes = signedDocument.data

        VerifyDocumentResponse verifiedDocument = supportServiceAPI.verifyDocument(profileConfig, signedDocument);

        then:
        verifiedDocument != null

        println "-----BEGIN VALIDATION REPORT-----"
        println new String(verifiedDocument.reportData)
        println "-----END VALIDATION REPORT-----"
        verifiedDocument.isVerifies()
    }

    def "perform CMS document signing and verification"(){
        when:
        // Create user that is going to sign the document(s)
        User user = new User.Builder()
                .userId("195207092072")
                .role("testrole")
                .build()

        // Create document requests to include in the transaction.
        DocumentRequests documentRequests = new DocumentRequests.Builder()
                .addCMSDocument("src/test/resources/testdocument.doc")
                .build()

        // Generate the prepared signature request using the support service API.
        PreparedSignatureResponse preparedSignature = supportServiceAPI.prepareSignature(
                profileConfig,
                documentRequests,
                null,
                "Im signing everything",
                user,
                "http://localhost:6060/eid2-dummy-idp/samlv2/idp/metadata",
                "http://localhost",
                null
        )

        // Send the signature request to central system to receive SAML request.
        Map<String,String> response = processSignRequest(preparedSignature.signRequest, preparedSignature.actionURL)

        // Send SAML request to identity provider to receive the SAML response.
        response = processAuthnRequest(response["SAMLRequest"] as String, response["RelayState"] as String, response["ActionURL"] as String, user.userId)

        // Send SAML response to central system to receive the sign response.
        response = processAuthnResponse(response["SAMLResponse"] as String, response["RelayState"] as String, response["ActionURL"] as String)

        // Process the sign response using the support service API in order to get the complete signed document.
        CompleteSignatureResponse completeSignature = supportServiceAPI.completeSignature(
                profileConfig,
                response["EidSignResponse"] as String,
                preparedSignature.transactionId
        )

        Document signedDocument = completeSignature.documents.documents.first() as Document
        new File("build/tmp/signed_${signedDocument.name}").bytes = signedDocument.data

        VerifyDocumentResponse verifiedDocument = supportServiceAPI.verifyDocument(profileConfig, signedDocument);

        then:
        verifiedDocument != null

        println "-----BEGIN VALIDATION REPORT-----"
        println new String(verifiedDocument.reportData)
        println "-----END VALIDATION REPORT-----"
        verifiedDocument.isVerifies()
    }

    private Map<String,String> processSignRequest(String signRequest, String actionURL) {
        Map<String,String> result = [:]
        String relayState = UUID.randomUUID().toString()

        def client = new OkHttpClient()
        RequestBody formBody = new FormBody.Builder()
                .add("EidSignRequest", signRequest)
                .add("RelayState", relayState)
                .build()

        def request = new Request.Builder()
                .url(actionURL)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .post(formBody)
                .build()

        client.newCall(request).execute().withCloseable { resp ->
            def xml = resp.body().charStream().withReader { reader ->
                return parseXmlStream(reader)
            }
            result.put("ActionURL", xml.body.form.@action.toString())
            result.put("SAMLRequest", xml.body.form.div.input.find { it.@name == "SAMLRequest" }.@value.toString())
            result.put("RelayState", xml.body.form.div.input.find { it.@name == "RelayState" }.@value.toString())
            result.put("EidSignResponse", xml.body.form.div.input.find { it.@name == "EidSignResponse" }.@value.toString())
        }
        return result
    }

    private Map<String,String> processAuthnRequest(String authnRequest, String relayState, String actionURL, String userId) {
        Map<String,String> result = [:]
        def client = new OkHttpClient()
        RequestBody formBody = new FormBody.Builder()
                .add("SAMLRequest", authnRequest)
                .add("RelayState", relayState)
                .add("PersonalNumber", userId)
                .build()

        def request = new Request.Builder()
                .url(actionURL)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .post(formBody)
                .build()

        client.newCall(request).execute().withCloseable { resp ->
            def xml = resp.body().charStream().withReader { reader ->
                return parseXmlStream(reader)
            }
            result.put("ActionURL", xml.body.form.@action.toString())
            result.put("SAMLResponse", xml.body.form.input.find { it.@name == "SAMLResponse" }.@value.toString())
            result.put("RelayState", xml.body.form.input.find { it.@name == "RelayState" }.@value.toString())
        }
        return result
    }

    private Map<String,String> processAuthnResponse(String authnResponse, String relayState, String actionURL) {
        Map<String,String> result = [:]

        def client = new OkHttpClient()
        RequestBody formBody = new FormBody.Builder()
                .add("SAMLResponse", authnResponse)
                .add("RelayState", relayState)
                .build()

        def request = new Request.Builder()
                .url(actionURL)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .post(formBody)
                .build()

        client.newCall(request).execute().withCloseable { resp ->
            def xml = resp.body().charStream().withReader { reader ->
                return parseXmlStream(reader)
            }
            result.put("ActionURL", xml.body.form.@action.toString())
            result.put("EidSignResponse", xml.body.form.div.input.find { it.@name == "EidSignResponse" }.@value.toString())
            result.put("RelayState", xml.body.form.div.input.find { it.@name == "RelayState" }.@value.toString())
        }
        return result
    }

    private static parseXmlStream(Reader reader) {
        def factory = SAXParserFactory.newInstance()
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
        return new XmlSlurper(factory.newSAXParser()).parse(reader)
    }
}