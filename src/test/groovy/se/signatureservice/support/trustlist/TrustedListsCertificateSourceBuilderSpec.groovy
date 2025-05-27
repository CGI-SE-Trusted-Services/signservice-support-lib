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
package se.signatureservice.support.trustlist

import com.fasterxml.jackson.databind.ObjectMapper
import eu.europa.esig.dss.model.DSSDocument
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.SignatureValue
import eu.europa.esig.dss.model.ToBeSigned
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import eu.europa.esig.dss.token.JKSSignatureToken
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.xades.TrustedListSignatureParametersBuilder
import eu.europa.esig.dss.xades.XAdESSignatureParameters
import eu.europa.esig.dss.xades.signature.XAdESService
import eu.europa.esig.trustedlist.TrustedListFacade
import eu.europa.esig.trustedlist.jaxb.tsl.*
import groovy.xml.XmlSlurper
import groovy.yaml.YamlSlurper
import org.bouncycastle.jce.provider.BouncyCastleProvider
import se.signatureservice.messages.utils.CertUtils
import se.signatureservice.support.api.v2.Document
import se.signatureservice.support.api.v2.DocumentSigningRequest
import se.signatureservice.support.api.v2.V2SupportServiceAPI
import se.signatureservice.support.api.v2.VerifyDocumentResponse
import se.signatureservice.support.common.cache.SimpleCacheProvider
import se.signatureservice.support.system.SupportAPIProfile
import se.signatureservice.support.utils.SupportLibraryUtils
import se.signatureservice.support.utils.TestHTTPServer
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServlet
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import javax.xml.datatype.DatatypeFactory
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate

import static jakarta.servlet.http.HttpServletResponse.*

/**
 * Unit test for TrustedListsCertificateSourceBuilder.
 *
 * @author Filip Wessman 2022-12-10
 */
class TrustedListsCertificateSourceBuilderSpec extends Specification {
    @Shared
    static TestHTTPServer mockedServer
    @Shared
    static TestHTTPServer mockedServerSE

    static X509Certificate testRecipientCert

    static Document testSignedPDFDocument
    static Document testSignedXMLDocument
    static Document testSignedCMSDocument
    static Document testSignedXMLNonETSIDocument
    static Document testUnsignedPDFDocument
    static Document testUnsignedXMLDocument
    static Document testUnsignedCMSDocument
    static Document testUntrustedSignedPDFDocument
    static Document testUntrustedSignedXMLDocument
    static Document testUntrustedSignedCMSDocument

    static Document euDSSTestSignedXMLDocument

    static V2SupportServiceAPI supportServiceAPI
    static List<Object> testDocuments = []
    static YamlSlurper yamlSlurper = new YamlSlurper()

    static SupportAPIProfile testProfile1 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile1.yml")) as Map)

    static String tempFolder = "build/tmp/TrustedListsCertificateSourceBuilderSpec"

    def setupSpec() {
        Security.addProvider(new BouncyCastleProvider())
        new File("build/tmp/TrustedListsCertificateSourceBuilderSpec").mkdirs()

        mockedServer = new TestHTTPServer()
        mockedServer.addHandler(mockedRemoteSignServerHandler(), "/")
        mockedServer.start()

        mockedServerSE = new TestHTTPServer()
        mockedServerSE.addHandler(mockedRemoteSignServerHandlerSE(), "/")
        mockedServerSE.start()

        CertUtils.installBCProvider()
        testRecipientCert = CertUtils.getCertfromByteArray(new File("src/test/resources/testrecipient.cer").bytes)

        setupTestLOTLFile()
        setupTestSETLFile()

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
                .trustedCertificateSource(new TrustedListsCertificateSourceBuilder("http://localhost:${mockedServer.port}/lotlurl", "http://localhost:${mockedServer.port}/ojurl", false, false, false, "build/tmp/TrustedListsCertificateSourceBuilderSpec/cache", 0, -1, "src/test/resources/keystore.jks", "JKS", "TSWCeC", null))
                .build() as V2SupportServiceAPI

        testDocuments.add(new DocumentSigningRequest(referenceId: "123456", type: "application/pdf", name: "testdocument-unsigned.pdf", data: new File("src/test/resources/testdocument.pdf").bytes))
        testDocuments.add(new DocumentSigningRequest(referenceId: "234567", type: "text/xml", name: "testdocument-unsigned.xml", data: new File("src/test/resources/testdocument.xml").bytes))
        testDocuments.add(new DocumentSigningRequest(referenceId: "345678", type: "application/octet-stream", name: "testdocument-unsigned.doc", data: new File("src/test/resources/testdocument.doc").bytes))

        testSignedPDFDocument = new Document(referenceId: "123456", type: "application/pdf", name: "testdocument-signed.pdf", data: new File("src/test/resources/signed-documents/testdocument-signed.pdf").bytes)
        testSignedXMLDocument = new Document(referenceId: "234567", type: "text/xml", name: "testdocument-signed.xml", data: new File("src/test/resources/signed-documents/testdocument-signed.xml").bytes)
        testSignedCMSDocument = new Document(referenceId: "345678", type: "application/msword", name: "testdocument-signed.doc", data: new File("src/test/resources/signed-documents/testdocument-signed.doc").bytes)
        testSignedXMLNonETSIDocument = new Document(referenceId: "456789", type: "text/xml", name: "testdocument_NonETSI.xml", data: new File("src/test/resources/signed-documents/testdocument_NonETSI.xml").bytes)
        testUnsignedPDFDocument = new Document(referenceId: "123456", type: "application/pdf", name: "testdocument.pdf", data: new File("src/test/resources/testdocument.pdf").bytes)
        testUnsignedXMLDocument = new Document(referenceId: "234567", type: "text/xml", name: "testdocument.xml", data: new File("src/test/resources/testdocument.xml").bytes)
        testUnsignedCMSDocument = new Document(referenceId: "345678", type: "application/msword", name: "testdocument.doc", data: new File("src/test/resources/testdocument.doc").bytes)
        testUntrustedSignedPDFDocument = new Document(referenceId: "123456", type: "application/pdf", name: "testdocument-untrusted.pdf", data: new File("src/test/resources/signed-documents/untrusted/testdocument-untrusted.pdf").bytes)
        testUntrustedSignedXMLDocument = new Document(referenceId: "234567", type: "text/xml", name: "testdocument-untrusted.xml", data: new File("src/test/resources/signed-documents/untrusted/testdocument-untrusted.xml").bytes)
        testUntrustedSignedCMSDocument = new Document(referenceId: "345678", type: "application/msword", name: "testdocument-untrusted.doc", data: new File("src/test/resources/signed-documents/untrusted/testdocument-untrusted.doc").bytes)

        /**
         * eu-lotl.xml
         * Tests pruned to fail when not maintained.
         * TODO <NextUpdate> 2024-05-07T14:10:01Z
         */
        euDSSTestSignedXMLDocument = new Document(referenceId: "133737", type: "text/xml", name: "OJ_C_2017_173_FULL.xml", data: new File("src/test/resources/signed-documents/dss-lib-signed/OJ_C_2017_173_FULL.xml").bytes)
    }

    def cleanupSpec() {
        new File("build/tmp/TrustedListsCertificateSourceBuilderSpec").deleteDir()

        if (mockedServer && mockedServer.isRunning()) {
            mockedServer.stop()
        }
    }

    static void setupTestLOTLFile(){
        def lotlURL = Files.copy(Paths.get("src/test/resources/trusted-lists/eu-lotl-minimal.xml"), Paths.get("${tempFolder}/eu-lotl-minimal.xml"), StandardCopyOption.REPLACE_EXISTING).toFile()

        def validationTruststore = KeyStore.getInstance("JKS")
        validationTruststore.load(new FileInputStream("src/test/resources/validation-trustedlists.jks"), "foo123".toCharArray())

        final TrustStatusListType jaxbLOTL = TrustedListFacade.newFacade().unmarshall(lotlURL, false)
        def TSLPointers = jaxbLOTL.getSchemeInformation().getPointersToOtherTSL().getOtherTSLPointer()

        def serviceDigitalIdentities = new ServiceDigitalIdentityListType()
        def digitalIdentityListType = new DigitalIdentityListType()
        def digitalIdentityType = new DigitalIdentityType()
        digitalIdentityType.setX509Certificate(validationTruststore.getCertificate("8af76eae8e1a201;cn=mock issuing ca,o=mockasiner ab,c=se").getEncoded())
        digitalIdentityListType.getDigitalId().add(digitalIdentityType)
        serviceDigitalIdentities.getServiceDigitalIdentity().add(digitalIdentityListType)
        def otherTSLPointer0 = TSLPointers.get(0)
        otherTSLPointer0.setServiceDigitalIdentities(serviceDigitalIdentities)
        def otherTSLPointer1 = TSLPointers.get(1)
        otherTSLPointer1.setServiceDigitalIdentities(serviceDigitalIdentities)

        TSLPointers.get(0).setTSLLocation("http://localhost:${mockedServer.port}/")
        TSLPointers.get(1).setTSLLocation("http://localhost:${mockedServerSE.port}/")

        DSSDocument unsigned_TL
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            TrustedListFacade.newFacade().marshall(jaxbLOTL, baos) // Validation against the related XSD
            unsigned_TL = new InMemoryDocument(baos.toByteArray())
        }

        try (InputStream is = new FileInputStream("src/test/resources/keystore.jks")
             JKSSignatureToken token = new JKSSignatureToken(is, new KeyStore.PasswordProtection("TSWCeC".toCharArray()))) {

            DSSPrivateKeyEntry privateKeyEntry = token.getKeys().get(0)
            CertificateToken signingCertificate = privateKeyEntry.getCertificate()

            TrustedListSignatureParametersBuilder builder = new TrustedListSignatureParametersBuilder(signingCertificate, unsigned_TL)
            XAdESSignatureParameters parameters = builder.build()

            XAdESService service = new XAdESService(new CommonCertificateVerifier())

            ToBeSigned dataToSign = service.getDataToSign(unsigned_TL, parameters)
            SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKeyEntry)
            DSSDocument signedTrustedList = service.signDocument(unsigned_TL, parameters, signatureValue)
            signedTrustedList.save("${tempFolder}/signedLOTL.xml")
        }
    }

    static void setupTestSETLFile() {
        def validationTruststore = KeyStore.getInstance("JKS")
        validationTruststore.load(new FileInputStream("src/test/resources/validation-truststore.jks"), "foo123".toCharArray())

        def validationTrustedlists = KeyStore.getInstance("JKS")
        validationTrustedlists.load(new FileInputStream("src/test/resources/validation-trustedlists.jks"), "foo123".toCharArray())

        def trustListSE = Files.copy(Paths.get("src/test/resources/trusted-lists/SE-TL-minimal.xml"), Paths.get("${tempFolder}/SE-TL-minimal.xml"), StandardCopyOption.REPLACE_EXISTING).toFile()

        final TrustStatusListType jaxbTLSE = TrustedListFacade.newFacade().unmarshall(trustListSE, false)

        def digitalIdentityListType = new DigitalIdentityListType()
        def digitalIdentityType = new DigitalIdentityType()
        digitalIdentityType.setX509Certificate(validationTrustedlists.getCertificate("8af76eae8e1a201;cn=mock issuing ca,o=mockasiner ab,c=se").getEncoded())
        digitalIdentityListType.getDigitalId().add(digitalIdentityType)

        def TSLPointers = jaxbTLSE.getSchemeInformation().getPointersToOtherTSL().getOtherTSLPointer().get(0)

        TSLPointers.getServiceDigitalIdentities().getServiceDigitalIdentity().add(digitalIdentityListType)
        TSLPointers.setTSLLocation("http://localhost:${mockedServer.port}/")

        for (String alias : validationTruststore.aliases()) {
            def digitalIdentityListType1 = new DigitalIdentityListType()
            def digitalIdentityType1 = new DigitalIdentityType()
            digitalIdentityType1.setX509Certificate(validationTruststore.getCertificate(alias).getEncoded())
            digitalIdentityListType1.getDigitalId().add(digitalIdentityType1)

            def tspService = new TSPServiceInformationType()
            tspService.setServiceTypeIdentifier("http://uri.etsi.org/TrstSvc/Svctype/CA/QC")
            def nameType = new InternationalNamesType()
            def nameTypeValue = new MultiLangNormStringType()
            nameTypeValue.setValue("CGI Signature Validation Service")
            nameTypeValue.setLang("en")
            nameType.getName().add(nameTypeValue)
            tspService.setServiceName(nameType)
            tspService.setServiceDigitalIdentity(digitalIdentityListType1)
            tspService.setServiceStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted")
            GregorianCalendar c = new GregorianCalendar()
            c.setTime(new Date())
            tspService.setStatusStartingTime(DatatypeFactory.newInstance().newXMLGregorianCalendar(c))
            def tspServiceType = new TSPServiceType()
            tspServiceType.setServiceInformation(tspService)
            jaxbTLSE.getTrustServiceProviderList().getTrustServiceProvider().get(0).getTSPServices().getTSPService().add(tspServiceType)
        }

        DSSDocument unsigned_TL
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            TrustedListFacade.newFacade().marshall(jaxbTLSE, baos)
            unsigned_TL = new InMemoryDocument(baos.toByteArray())
        }

        try (InputStream is = new FileInputStream("src/test/resources/keystore.jks")
             JKSSignatureToken token = new JKSSignatureToken(is, new KeyStore.PasswordProtection("TSWCeC".toCharArray()))) {

            DSSPrivateKeyEntry privateKeyEntry = token.getKeys().get(0)
            CertificateToken signingCertificate = privateKeyEntry.getCertificate()

            TrustedListSignatureParametersBuilder builder = new TrustedListSignatureParametersBuilder(signingCertificate, unsigned_TL)
            XAdESSignatureParameters parameters = builder.build()

            XAdESService service = new XAdESService(new CommonCertificateVerifier())

            ToBeSigned dataToSign = service.getDataToSign(unsigned_TL, parameters)
            SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKeyEntry)
            DSSDocument signedTrustedList = service.signDocument(unsigned_TL, parameters, signatureValue)
            signedTrustedList.save("${tempFolder}/signedTrustedList.xml")
        }
    }

    def mockedRemoteSignServerHandler() {
        return new HttpServlet() {
            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
                try (def outputStream = response.getOutputStream()) {
                    String xmlString = null
                    def uriPath = request.getRequestURI().trim().toLowerCase()
                    if (uriPath == "/lotlurl") {
                        xmlString = new File("${tempFolder}/signedLOTL.xml").text
                    } else if(uriPath == "/ojurl") {
                        //xmlString = Files.copy(Paths.get("src/test/resources/officialJournal.html"), Paths.get("${tempDir}/officialJournal.html"), StandardCopyOption.REPLACE_EXISTING).toFile().text
                        xmlString = Files.copy(Paths.get("src/test/resources/officialJournal_Minimal.html"), Paths.get("${tempFolder}/officialJournal_Minimal.html"), StandardCopyOption.REPLACE_EXISTING).toFile().text
                    } else {
                        response.sendError(SC_NOT_FOUND, "Invalid target.")
                    }

                    response.setStatus(SC_OK)
                    response.setContentType((uriPath == "/ojurl" ? "text/html; charset=UTF-8" : "application/xml"))
                    //outputStream.write(xmlString.getBytes(StandardCharsets.UTF_8))
                    outputStream.write(xmlString.getBytes())
                } catch (Exception e) {
                    response.sendError(SC_BAD_REQUEST, e.getMessage())
                    e.printStackTrace()
                    throw e
                }
            }
        }
    }

    def mockedRemoteSignServerHandlerSE() {
        return new HttpServlet() {
            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
                try (def outputStream = response.getOutputStream()) {
                    response.setStatus(SC_OK)
                    response.setContentType("application/xml;charset=UTF-8")
                    outputStream.write(new File("${tempFolder}/signedTrustedList.xml").text.getBytes(StandardCharsets.UTF_8))
                } catch (Exception e) {
                    response.sendError(SC_BAD_REQUEST, e.getMessage())
                    e.printStackTrace()
                    throw e
                }
            }
        }
    }

    @Unroll
    def "Test LOTL verifyDocument on #documentType document"() {
        when:
            VerifyDocumentResponse response = supportServiceAPI.verifyDocument(testProfile1, testDocument)
            println new String(response.reportData)
            def xmlReport = new XmlSlurper().parseText(new String(response.reportData))
            X509Certificate signingCertificate = CertUtils.getX509CertificateFromPEMorDER(response.signatures.signer.first().signerCertificate)

        then:
            response.verifies
            xmlReport.Signature[0].@SignatureFormat == expectedSignatureFormat
            xmlReport.Signature[0].Indication == "TOTAL_PASSED"
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
            testDocument          | documentType | expectedSignatureFormat | expectedSignerId      | expectedSigningAlgorithm
            testSignedXMLDocument | "XML"        | "XAdES-BASELINE-B"      | "PNOSE-195207092072"  | "SHA256withRSAandMGF1"
            testSignedPDFDocument | "PDF"        | "PAdES-BASELINE-B"      | "195207092072"        | "SHA256withRSA"
            testSignedCMSDocument | "CMS"        | "CAdES-BASELINE-B"      | "195207092072"        | "SHA256withRSA"
    }

    @Unroll
    def "Test LOTL verifyDocument on #documentType untrusted document"() {
        when:
            VerifyDocumentResponse response = supportServiceAPI.verifyDocument(testProfile1, testDocument)
            println new String(response.reportData)
            def xmlReport = new XmlSlurper().parseText(new String(response.reportData))
            X509Certificate signingCertificate = CertUtils.getX509CertificateFromPEMorDER(response.signatures.signer.first().signerCertificate)

        then:
            !response.verifies
            xmlReport.Signature[0].@SignatureFormat == expectedSignatureFormat
            xmlReport.Signature[0].Indication == "INDETERMINATE"
            xmlReport.Signature[0].SubIndication == "NO_CERTIFICATE_CHAIN_FOUND"
            response.reportData != null
            response.reportMimeType == "text/xml"
            response.referenceId == testDocument.referenceId
            response.signatures != null
            response.signatures.signer != null
            response.signatures.signer.size() == 1
            response.signatures.signer.get(0).issuerId == "C=SE,O=Mockasiner AB,CN=Mock Issuing CA"
            response.signatures.signer.get(0).signingAlgorithm == "SHA256withRSA"
            response.signatures.signer.get(0).signingDate.after(signingCertificate.notBefore)
            response.signatures.signer.get(0).signingDate.before(signingCertificate.notAfter)
            response.signatures.signer.get(0).validFrom == signingCertificate.notBefore
            response.signatures.signer.get(0).validTo == signingCertificate.notAfter

        where:
            testDocument                   | documentType | expectedSignatureFormat
            testUntrustedSignedXMLDocument | "XML"        | "XAdES-BASELINE-B"
            testUntrustedSignedPDFDocument | "PDF"        | "PAdES-BASELINE-B"
            testUntrustedSignedCMSDocument | "CMS"        | "CAdES-BASELINE-B"
    }

    @Unroll
    def "Test LOTL verifyDocument on unsigned #documentType document"() {
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

    def "Test LOTL verifyDocument signed with XML DSig"() {
        when:
            VerifyDocumentResponse response = supportServiceAPI.verifyDocument(testProfile1, testSignedXMLNonETSIDocument)
            println new String(response.reportData)
            def xmlReport = new XmlSlurper().parseText(new String(response.reportData))
            X509Certificate signingCertificate = CertUtils.getX509CertificateFromPEMorDER(response.signatures.signer.first().signerCertificate)

        then:
            response.verifies
            xmlReport.Signature[0].@SignatureFormat == "XML-NOT-ETSI"
            xmlReport.Signature[0].Indication == "TOTAL_PASSED"
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

    def "Test LOTL verifyDocument with modified XML"() {
        setup:
            byte[] originalData = testSignedXMLDocument.data

        when:
            testSignedXMLDocument.data = new String(originalData, "UTF-8").replaceAll("Heisenberg", "Heisenburg").getBytes("UTF-8")
            VerifyDocumentResponse response = supportServiceAPI.verifyDocument(testProfile1, testSignedXMLDocument)
            def xmlReport = new XmlSlurper().parseText(new String(response.reportData))
            println new String(response.reportData)

        then:
            !response.verifies
            xmlReport.Signature[0].@SignatureFormat == "XAdES-BASELINE-B"
            xmlReport.Signature[0].Indication == "TOTAL_FAILED"
            xmlReport.Signature[0].SubIndication == "SIG_CRYPTO_FAILURE"
            xmlReport.Signature[0].AdESValidationDetails.Error == "The signature is not intact!"

        cleanup:
            testSignedXMLDocument.data = originalData
    }

    @Unroll
    def "Test verifyDocument on #documentType document, using both official LOTL and custom KeystoreCertificateSource certificates parsed."() {
        setup:
            TrustedListsCertificateSourceBuilder trustedListsCertificateSourceBuilder1 =
                    new TrustedListsCertificateSourceBuilder("https://ec.europa.eu/tools/lotl/eu-lotl.xml", "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG", false, false, false, "build/tmp/TrustedListsCertificateSourceBuilderSpec/cache", 0, -1, "src/test/resources/oj-keystore.p12", "PKCS12", "dss-password", new KeyStoreCertificateSource("src/test/resources/validation-truststore.jks", "jks", "foo123".toCharArray()))
            V2SupportServiceAPI supportServiceAPI1 = new V2SupportServiceAPI.Builder()
                    .messageSecurityProvider(SupportLibraryUtils.createSimpleMessageSecurityProvider(
                            "src/test/resources/keystore.jks",
                            "TSWCeC",
                            "8af76eae8e1a201;cn=mock issuing ca,o=mockasiner ab,c=se",
                            "src/test/resources/truststore.jks",
                            "foo123"
                    ))
                    .cacheProvider(new SimpleCacheProvider())
                    .addSignMessageRecipient("https://m00-mg-local.idpst.funktionstjanster.se/samlv2/idp/metadata/6/7", testRecipientCert)
                    .trustedCertificateSource(trustedListsCertificateSourceBuilder1)
                    .build() as V2SupportServiceAPI

        when:
            VerifyDocumentResponse response = supportServiceAPI1.verifyDocument(testProfile1, testDocument)
            println new String(response.reportData)
            def xmlReport = new XmlSlurper().parseText(new String(response.reportData))
            X509Certificate signingCertificate = CertUtils.getX509CertificateFromPEMorDER(response.signatures.signer.first().signerCertificate)

        then:
            // Usually when it fails it's on https://ec.europa.eu/tools/lotl/eu-lotl.xml part. Wait and test again.

            //  For euDSSTestSignedXMLDocument, the corresponding test in the eu-lib, DSS2058Test, gets INDETERMINATE indication
            if (testDocument == euDSSTestSignedXMLDocument) {
                !response.verifies
                xmlReport.Signature[0].Indication == "INDETERMINATE"
            } else {
                response.verifies
                xmlReport.Signature[0].Indication == "TOTAL_PASSED"
            }

            xmlReport.Signature[0].@SignatureFormat == expectedSignatureFormat
            response.reportData != null
            response.reportMimeType == "text/xml"
            response.referenceId == testDocument.referenceId
            response.signatures != null
            response.signatures.signer != null
            response.signatures.signer.size() == 1
            response.signatures.signer.get(0).issuerId.contains(issuerId)
            response.signatures.signer.get(0).signingAlgorithm == expectedSigningAlgorithm
            response.signatures.signer.get(0).signingDate.after(signingCertificate.notBefore)
            response.signatures.signer.get(0).signingDate.before(signingCertificate.notAfter)
            response.signatures.signer.get(0).validFrom == signingCertificate.notBefore
            response.signatures.signer.get(0).validTo == signingCertificate.notAfter

        where:
            testDocument                | expectedSignatureFormat    | expectedSigningAlgorithm   | issuerId                                 | documentType
            testSignedXMLDocument       | "XAdES-BASELINE-B"         | "SHA256withRSAandMGF1"     | "CN=sub Network - Development"           | "XML"
            testSignedPDFDocument       | "PAdES-BASELINE-B"         | "SHA256withRSA"            | "CN=sub Network - Development"           | "PDF"
            testSignedCMSDocument       | "CAdES-BASELINE-B"         | "SHA256withRSA"            | "CN=sub Network - Development"           | "CMS"
            euDSSTestSignedXMLDocument  | "XAdES-BASELINE-LTA"       | "SHA256withRSA"            | "CN=LuxTrust Global Qualified CA 3,O"    | "XML"  // Test pruned to fail when not maintained and/or EU-DSS updates https://ec.europa.eu/tools/lotl/eu-lotl.xml. <NextUpdate> 2024-05-07T14:10:01Z for eu-lotl.xml
    }

    def "Test that getCertificateVerifier returns correct class instance"() {
        when:
            def certificateVerifier = supportServiceAPI.getCertificateVerifier()
        then:
            certificateVerifier instanceof CommonCertificateVerifier
            certificateVerifier.trustedCertSources.sources.get(0) instanceof TrustedListsCertificateSource
    }

    @Unroll
    def "Test LOTL verifyDocument on #documentType document and that it's able to parse LOTL files from cache when using OfflineLoader and OnlineLoader respectively"() {
        setup:
            new TrustedListsCertificateSourceBuilder("http://localhost:${mockedServer.port}/lotlurl", "http://localhost:${mockedServer.port}/ojurl", false, false, false, "build/tmp/TrustedListsCertificateSourceBuilderSpec/cacheTest", expirationTimeOnlineLoader, expirationTimeOfflineLoader, "src/test/resources/keystore.jks", "JKS", "TSWCeC", null)
            def tlcsb = new TrustedListsCertificateSourceBuilder("http://localhost:${mockedServer.port}/lotlurl", "http://localhost:${mockedServer.port}/ojurl", useOfflineLoader, false, false, "build/tmp/TrustedListsCertificateSourceBuilderSpec/cacheTest", expirationTimeOnlineLoader, expirationTimeOfflineLoader, "src/test/resources/keystore.jks", "JKS", "TSWCeC", null)
            V2SupportServiceAPI supportServiceAPI1 = new V2SupportServiceAPI.Builder()
                    .messageSecurityProvider(SupportLibraryUtils.createSimpleMessageSecurityProvider(
                            "src/test/resources/keystore.jks",
                            "TSWCeC",
                            "8af76eae8e1a201;cn=mock issuing ca,o=mockasiner ab,c=se",
                            "src/test/resources/truststore.jks",
                            "foo123"
                    ))
                    .cacheProvider(new SimpleCacheProvider())
                    .addSignMessageRecipient("https://m00-mg-local.idpst.funktionstjanster.se/samlv2/idp/metadata/6/7", testRecipientCert)
                    .trustedCertificateSource(tlcsb)
                    .build() as V2SupportServiceAPI

        when:
            VerifyDocumentResponse response = supportServiceAPI1.verifyDocument(testProfile1, testDocument)
            println new String(response.reportData)
            def xmlReport = new XmlSlurper().parseText(new String(response.reportData))
            X509Certificate signingCertificate = CertUtils.getX509CertificateFromPEMorDER(response.signatures.signer.first().signerCertificate)

        then:
            response.verifies
            xmlReport.Signature[0].@SignatureFormat == expectedSignatureFormat
            xmlReport.Signature[0].Indication == "TOTAL_PASSED"
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

        cleanup:
            new File("build/tmp/TrustedListsCertificateSourceBuilderSpec/cacheTest").deleteDir()

        where:
            testDocument          | documentType | expectedSignatureFormat  | expectedSigningAlgorithm   | useOfflineLoader  | expirationTimeOnlineLoader    | expirationTimeOfflineLoader | expectedSignerId
            testSignedXMLDocument | "XML"        | "XAdES-BASELINE-B"       | "SHA256withRSAandMGF1"     | false             | -1                            | -1                          | "PNOSE-195207092072"
            testSignedXMLDocument | "XML"        | "XAdES-BASELINE-B"       | "SHA256withRSAandMGF1"     | true              | 0                             | -1                          | "PNOSE-195207092072"
            testSignedPDFDocument | "PDF"        | "PAdES-BASELINE-B"       | "SHA256withRSA"            | false             | -1                            | -1                          | "195207092072"
            testSignedPDFDocument | "PDF"        | "PAdES-BASELINE-B"       | "SHA256withRSA"            | true              | 0                             | -1                          | "195207092072"
            testSignedCMSDocument | "CMS"        | "CAdES-BASELINE-B"       | "SHA256withRSA"            | false             | -1                            | -1                          | "195207092072"
            testSignedCMSDocument | "CMS"        | "CAdES-BASELINE-B"       | "SHA256withRSA"            | true              | 0                             | -1                          | "195207092072"
    }

    @Unroll
    def "Test that TrustedListsCertificateSourceBuilder is able to parse LOTL files from cache when using OfflineLoader and OnlineLoader respectively."() {
        when:
            new TrustedListsCertificateSourceBuilder("http://localhost:${mockedServer.port}/lotlurl", "http://localhost:${mockedServer.port}/ojurl", false, "build/tmp/TrustedListsCertificateSourceBuilderSpec/cacheTest", expirationTimeOnlineLoader, expirationTimeOfflineLoader)
            def tlcsb = new TrustedListsCertificateSourceBuilder("http://localhost:${mockedServer.port}/lotlurl", "http://localhost:${mockedServer.port}/ojurl", useOfflineLoader, "build/tmp/TrustedListsCertificateSourceBuilderSpec/cacheTest", expirationTimeOnlineLoader, expirationTimeOfflineLoader)

        then:
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getUrl() == "http://localhost:${mockedServerSE.port}/"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getDownloadCacheInfo().cacheState.toString() == "SYNCHRONIZED"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getParsingCacheInfo().getTSLType().getUri() == "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getParsingCacheInfo().getTSLType().getLabel() == "EU Trusted List"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getParsingCacheInfo().getTSLType().toString() == "EUgeneric"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getParsingCacheInfo().getSequenceNumber() == 46
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getParsingCacheInfo().getVersion() == 5
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getParsingCacheInfo().getTerritory() == "SE"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getParsingCacheInfo().getTrustServiceProviders().get(0).getNames().get("en").get(0) == "CGI AB Test"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getValidationCacheInfo().getIndication().name() == "TOTAL_PASSED"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getTLInfos().get(0).getValidationCacheInfo().cacheState.toString() == "SYNCHRONIZED"

            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getUrl() == "http://localhost:${mockedServer.port}/lotlurl"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getDownloadCacheInfo().cacheState.toString() == "SYNCHRONIZED"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getTSLType().getUri() == "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getTSLType().getLabel() == "EU List of the Trusted Lists"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getTSLType().toString() == "EUlistofthelists"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getSequenceNumber() == 316
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getVersion() == 5
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getTerritory() == "EU"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getLotlOtherPointers().get(0).getTSLLocation() == "http://localhost:${mockedServer.port}/"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getLotlOtherPointers().get(0).getSdiCertificates().get(0).getCertificate().getIssuerDN().toString() == "CN=Mock Issuing CA,O=Mockasiner AB,C=SE"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getLotlOtherPointers().get(0).getSdiCertificates().get(0).getCertificate().getSubjectDN().toString() == "CN=Signature Support Service Dev,O=Mockasiner AB,C=SE"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getLotlOtherPointers().get(0).getSdiCertificates().get(0).getCertificate().getSigAlgName() == "SHA256WITHRSA"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getTlOtherPointers().get(0).getTSLLocation() == "http://localhost:${mockedServerSE.port}/"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getTlOtherPointers().get(0).getSdiCertificates().get(0).getCertificate().getIssuerDN().toString() == "CN=Mock Issuing CA,O=Mockasiner AB,C=SE"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().getTlOtherPointers().get(0).getSdiCertificates().get(0).getCertificate().getSigAlgName() == "SHA256WITHRSA"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().cacheState.toString() == "SYNCHRONIZED"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getValidationCacheInfo().getIndication().name() == "INDETERMINATE"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getValidationCacheInfo().getSubIndication().name() == "NO_CERTIFICATE_CHAIN_FOUND"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getValidationCacheInfo().getSigningCertificate().getCertificate().getIssuerDN().toString() == "CN=Mock Issuing CA,O=Mockasiner AB,C=SE"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getValidationCacheInfo().getSigningCertificate().getCertificate().getSubjectDN().toString() == "CN=Signature Support Service Dev,O=Mockasiner AB,C=SE"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getValidationCacheInfo().getSigningCertificate().getCertificate().getSigAlgName() == "SHA256WITHRSA"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getValidationCacheInfo().cacheState.toString() == "SYNCHRONIZED"

            tlcsb.job.cacheAccessFactory.downloadCache.keys.size() == 2
            tlcsb.job.cacheAccessFactory.parsingCache.keys.size() == 2
            tlcsb.job.cacheAccessFactory.validationCache.keys.size() == 2

        cleanup:
            new File("build/tmp/TrustedListsCertificateSourceBuilderSpec/cacheTest").deleteDir()

        where:
            useOfflineLoader    | expirationTimeOnlineLoader    | expirationTimeOfflineLoader
            false               | -1                            | -1
            true                | 0                             | -1
    }

    def "Test that TrustedListsCertificateSourceBuilder is unable to parse from cache when cached files have a expiration time set to 0."() {
        when:
            new TrustedListsCertificateSourceBuilder("http://localhost:${mockedServer.port}/lotlurl", "http://localhost:${mockedServer.port}/ojurl", false,"build/tmp/TrustedListsCertificateSourceBuilderSpec/cacheTest", 0, 0)
            def tlcsb = new TrustedListsCertificateSourceBuilder("http://localhost:${mockedServer.port}/lotlurl", "http://localhost:${mockedServer.port}/ojurl", true, "build/tmp/TrustedListsCertificateSourceBuilderSpec/cacheTest", 0, 0)

        then:
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).tlInfos.size() == 0
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getUrl() == "http://localhost:${mockedServer.port}/lotlurl"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getDownloadCacheInfo().cacheState.toString() == "ERROR"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getDownloadCacheInfo().exceptionMessage.toString() == "Cannot retrieve data from url [http://localhost:${mockedServer.port}/lotlurl]. Empty content is obtained!"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getParsingCacheInfo().cacheState.toString() == "REFRESH_NEEDED"
            tlcsb.trustedListsCertificateSource.getSummary().getLOTLInfos().get(0).getValidationCacheInfo().cacheState.toString() == "REFRESH_NEEDED"

        cleanup:
            new File("build/tmp/TrustedListsCertificateSourceBuilderSpec/cacheTest").deleteDir()
    }

    static SupportAPIProfile getProfile(Map profileData) {
        ObjectMapper objectMapper = new ObjectMapper()
        return objectMapper.convertValue(profileData, SupportAPIProfile.class)
    }
}
