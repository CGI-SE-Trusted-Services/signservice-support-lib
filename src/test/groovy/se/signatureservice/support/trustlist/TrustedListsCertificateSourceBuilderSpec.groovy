package se.signatureservice.support.trustlist

import com.fasterxml.jackson.databind.ObjectMapper
import eu.europa.esig.dss.model.*
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.token.DSSPrivateKeyEntry
import eu.europa.esig.dss.token.JKSSignatureToken
import eu.europa.esig.dss.validation.CommonCertificateVerifier
import eu.europa.esig.dss.xades.TrustedListSignatureParametersBuilder
import eu.europa.esig.dss.xades.XAdESSignatureParameters
import eu.europa.esig.dss.xades.signature.XAdESService
import eu.europa.esig.trustedlist.TrustedListFacade
import eu.europa.esig.trustedlist.jaxb.tsl.*
import groovy.xml.XmlSlurper
import groovy.yaml.YamlSlurper
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservice.testutils.TestHTTPServer
import org.certificateservices.messages.utils.CertUtils
import se.signatureservice.support.api.v2.Document
import se.signatureservice.support.api.v2.DocumentSigningRequest
import se.signatureservice.support.api.v2.V2SupportServiceAPI
import se.signatureservice.support.api.v2.VerifyDocumentResponse
import se.signatureservice.support.common.cache.SimpleCacheProvider
import se.signatureservice.support.system.SupportAPIProfile
import se.signatureservice.support.utils.SupportLibraryUtils
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import javax.servlet.ServletException
import javax.servlet.http.HttpServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.xml.datatype.DatatypeFactory
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST
import static javax.servlet.http.HttpServletResponse.SC_OK

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

    static Document realTestSignedXMLDocument
    static Document realTestSignedXMLDocument1
    static Document realTestSignedXMLDocument2
    static Document realTestSignedXMLDocument3
    static Document realTestSignedXMLDocument4
    static Document realTestSignedXMLDocument5
    static Document realTestSignedXMLDocument6
    static Document realTestSignedXMLDocument7
    static Document realTestSignedXMLDocument8
    static Document realTestSignedXMLDocument9
    static Document realTestSignedXMLDocument10
    static Document realTestSignedXMLDocument11

    static V2SupportServiceAPI supportServiceAPI
    static List<Object> testDocuments = []
    static YamlSlurper yamlSlurper = new YamlSlurper()
    static SupportAPIProfile testProfile1 = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile1.yml")) as Map)

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
                .trustedCertificateSource(new TrustedListsCertificateSourceBuilder("http://localhost:${mockedServer.port}/lotlurl", "http://localhost:${mockedServer.port}/ojurl", "src/test/resources/keystore.jks", "JKS", "TSWCeC").getTrustedCertificateSource())
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

        realTestSignedXMLDocument = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-AT-1.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-AT-1.xml").bytes)
        realTestSignedXMLDocument1 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-BE_ECON-3.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-BE_ECON-3.xml").bytes)
        realTestSignedXMLDocument2 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-BG-1.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-BG-1.xml").bytes)
        realTestSignedXMLDocument3 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-CY-1.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-CY-1.xml").bytes)
        realTestSignedXMLDocument4 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-CZ_ICZ-1.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-CZ_ICZ-1.xml").bytes)
        realTestSignedXMLDocument5 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-CZ_SEF-4.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-CZ_SEF-4.xml").bytes)
        realTestSignedXMLDocument6 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-CZ_SEF-5.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-CZ_SEF-5.xml").bytes)
        realTestSignedXMLDocument7 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-ES-100.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-ES-100.xml").bytes)
        realTestSignedXMLDocument8 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-ES-103.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-ES-103.xml").bytes)
        realTestSignedXMLDocument9 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-FR_NOT-3.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-FR_NOT-3.xml").bytes)
        realTestSignedXMLDocument10 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-HR_FIN-1.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-HR_FIN-1.xml").bytes)
        realTestSignedXMLDocument11 = new Document(referenceId: "123456", type: "text/xml", name: "Signature-X-HU_MIC-1.xml", data: new File("src/test/resources/signed-documents/eu-signed/Signature-X-HU_MIC-1.xml").bytes)
    }

    def cleanupSpec() {
        new File("build/tmp/TrustedListsCertificateSourceBuilderSpec").deleteDir()

        if (mockedServer && mockedServer.isRunning()) {
            mockedServer.stop()
        }
    }

    def mockedRemoteSignServerHandler() {
        return new HttpServlet() {
            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
                try (def outputStream = response.getOutputStream()) {
                    String xmlString
                    def uriPath = request.getRequestURI().trim().toLowerCase()
                    def tempDir = File.createTempDir().toPath()
                    if (uriPath == "/lotlurl") {
                        def lotlURL = Files.copy(Paths.get("src/test/resources/trusted-lists/eu-lotl-minimal.xml"), Paths.get("${tempDir}/eu-lotl-minimal.xml"), StandardCopyOption.REPLACE_EXISTING).toFile()

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
                        unsigned_TL.save("${tempDir}/unsigned_LOTL.xml")

                        DSSDocument trustedList = new FileDocument("${tempDir}/unsigned_LOTL.xml")


                        try (InputStream is = new FileInputStream("src/test/resources/keystore.jks")
                             JKSSignatureToken token = new JKSSignatureToken(is, new KeyStore.PasswordProtection("TSWCeC".toCharArray()))) {

                            DSSPrivateKeyEntry privateKeyEntry = token.getKeys().get(0)
                            CertificateToken signingCertificate = privateKeyEntry.getCertificate()

                            TrustedListSignatureParametersBuilder builder = new TrustedListSignatureParametersBuilder(signingCertificate, trustedList)
                            XAdESSignatureParameters parameters = builder.build()

                            XAdESService service = new XAdESService(new CommonCertificateVerifier())

                            ToBeSigned dataToSign = service.getDataToSign(trustedList, parameters)
                            SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKeyEntry)
                            DSSDocument signedTrustedList = service.signDocument(trustedList, parameters, signatureValue)
                            signedTrustedList.save("${tempDir}/signedLOTL.xml")
                        }

                        xmlString = new File("${tempDir}/signedLOTL.xml").text
                    } else {
                        xmlString = Files.copy(Paths.get("src/test/resources/cellar_a1dcada9-bfe9-11e9-9d01-01aa75ed71a1.xml"), Paths.get("${tempDir}/cellar_a1dcada9-bfe9-11e9-9d01-01aa75ed71a1.xml"), StandardCopyOption.REPLACE_EXISTING).toFile().text
                    }

                    response.setStatus(SC_OK)
                    response.setContentType("application/xml;charset=UTF-8")
                    outputStream.write(xmlString.getBytes(StandardCharsets.UTF_8))
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
                    def tempDir = File.createTempDir().toPath()

                    def validationTruststore = KeyStore.getInstance("JKS")
                    validationTruststore.load(new FileInputStream("src/test/resources/validation-truststore.jks"), "foo123".toCharArray())

                    def validationTrustedlists = KeyStore.getInstance("JKS")
                    validationTrustedlists.load(new FileInputStream("src/test/resources/validation-trustedlists.jks"), "foo123".toCharArray())

                    def trustListSE = Files.copy(Paths.get("src/test/resources/trusted-lists/SE-TL-minimal.xml"), Paths.get("${tempDir}/SE-TL-minimal.xml"), StandardCopyOption.REPLACE_EXISTING).toFile()

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
                    unsigned_TL.save("${tempDir}/unsigned_TL.xml")

                    DSSDocument trustedList = new FileDocument("${tempDir}/unsigned_TL.xml")

                    try (InputStream is = new FileInputStream("src/test/resources/keystore.jks")
                         JKSSignatureToken token = new JKSSignatureToken(is, new KeyStore.PasswordProtection("TSWCeC".toCharArray()))) {

                        DSSPrivateKeyEntry privateKeyEntry = token.getKeys().get(0)
                        CertificateToken signingCertificate = privateKeyEntry.getCertificate()

                        TrustedListSignatureParametersBuilder builder = new TrustedListSignatureParametersBuilder(signingCertificate, trustedList)
                        XAdESSignatureParameters parameters = builder.build()

                        XAdESService service = new XAdESService(new CommonCertificateVerifier())

                        ToBeSigned dataToSign = service.getDataToSign(trustedList, parameters)
                        SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKeyEntry)
                        DSSDocument signedTrustedList = service.signDocument(trustedList, parameters, signatureValue)
                        signedTrustedList.save("${tempDir}/signedTrustedList.xml")
                    }

                    String xmlString = new File("${tempDir}/signedTrustedList.xml").text

                    response.setStatus(SC_OK)
                    response.setContentType("application/xml;charset=UTF-8")
                    outputStream.write(xmlString.getBytes(StandardCharsets.UTF_8))
                } catch (Exception e) {
                    response.sendError(SC_BAD_REQUEST, e.getMessage())
                    e.printStackTrace()
                    throw e
                }
            }
        }
    }

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
        response.signatures.signer.get(0).signerId == "195207092072"
        response.signatures.signer.get(0).issuerId == "CN=sub Network - Development"
        response.signatures.signer.get(0).signingAlgorithm == "SHA256withRSA"
        response.signatures.signer.get(0).signingDate.after(signingCertificate.notBefore)
        response.signatures.signer.get(0).signingDate.before(signingCertificate.notAfter)
        response.signatures.signer.get(0).validFrom == signingCertificate.notBefore
        response.signatures.signer.get(0).validTo == signingCertificate.notAfter

        where:
        testDocument          | documentType | expectedSignatureFormat
        testSignedXMLDocument | "XML"        | "XAdES-BES"
        testSignedPDFDocument | "PDF"        | "PAdES-BASELINE-B"
        testSignedCMSDocument | "CMS"        | "CAdES-BASELINE-B"
    }


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
        xmlReport.Signature[0].@SignatureFormat == "XAdES-BES"
        xmlReport.Signature[0].Indication == "TOTAL_FAILED"
        xmlReport.Signature[0].SubIndication == "SIG_CRYPTO_FAILURE"
        xmlReport.Signature[0].AdESValidationDetails.Error == "The signature is not intact!"

        cleanup:
        testSignedXMLDocument.data = originalData
    }

    def "Test that getCertificateVerifier returns correct class instance"() {
        when:
        def certificateVerifier = supportServiceAPI.getCertificateVerifier()
        then:
        certificateVerifier instanceof CommonCertificateVerifier
        certificateVerifier.trustedCertSources.sources.get(0) instanceof TrustedListsCertificateSource
    }

    def "Test httpServer lotlurl"() {
        when:
        Request builder = new Request.Builder()
                .url("http://localhost:${mockedServer.port}/lotlurl").get().build()
        then:
        try (Response response = new OkHttpClient.Builder().build().newCall(builder).execute()) {
            if (!response.isSuccessful()) {
                throw new Exception("code: ${response.code()}, message: ${response.message()}")
            }
            def responseXML = new String(response.body().bytes(), StandardCharsets.UTF_8)
            System.out.println(responseXML)
        } catch (Exception e) {
            throw new Exception("Error sending request message to URL: ${e.getMessage()}", e.getCause())
        }
    }

    def "Test httpServer ojurl"() {
        when:
        Request builder = new Request.Builder()
                .url("http://localhost:${mockedServer.port}/ojurl").get().build()
        then:
        try (Response response = new OkHttpClient.Builder().build().newCall(builder).execute()) {
            if (!response.isSuccessful()) {
                throw new Exception("code: ${response.code()}, message: ${response.message()}")
            }
            def responseXML = new String(response.body().bytes(), StandardCharsets.UTF_8)
            System.out.println(responseXML)
        } catch (Exception e) {
            throw new Exception("Error sending request message to URL: ${e.getMessage()}", e.getCause())
        }
    }

    def "Test that TrustedListsCertificateSourceBuilder parses correct urls"() {
        when:
        def tlcsb = new TrustedListsCertificateSourceBuilder("url1")
        def TLVJS = tlcsb.getTLValidationJob().getSummary()
        then:
        "url1" == TLVJS.getLOTLInfos().get(0).getUrl()
    }

    static SupportAPIProfile getProfile(Map profileData) {
        ObjectMapper objectMapper = new ObjectMapper()
        return objectMapper.convertValue(profileData, SupportAPIProfile.class)
    }
}
