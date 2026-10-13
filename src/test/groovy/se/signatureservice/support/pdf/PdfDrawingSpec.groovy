package se.signatureservice.support.pdf

import com.fasterxml.jackson.databind.ObjectMapper
import eu.europa.esig.dss.enumerations.SignerTextPosition
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.pades.SignatureFieldParameters
import eu.europa.esig.dss.pades.SignatureImageParameters
import eu.europa.esig.dss.pades.SignatureImageTextParameters
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import groovy.yaml.YamlSlurper
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.PDDocument
import se.signatureservice.messages.DummyMessageSecurityProvider
import se.signatureservice.messages.utils.CertUtils
import se.signatureservice.support.api.SupportServiceAPI
import se.signatureservice.support.api.v2.Document
import se.signatureservice.support.api.v2.V2SupportServiceAPI
import se.signatureservice.support.api.v2.VerifyDocumentResponse
import se.signatureservice.support.system.SupportAPIProfile
import spock.lang.Specification

import java.awt.Color

class PdfDrawingSpec extends Specification {

    private static final YamlSlurper yamlSlurper = new YamlSlurper()
    private static SupportServiceAPI supportServiceAPI
    private static SupportAPIProfile testProfile1_for_test

    private final String unsignedPdf = "src/test/resources/testdocument.pdf"
    private final String signedPdf = "src/test/resources/signed-documents/testdocument-signed.pdf"

    void setupSpec() {
        CertUtils.installBCProvider()
        testProfile1_for_test = getProfile(yamlSlurper.parse(new File("src/test/resources/profiles/testProfile1-for-test.yml")) as Map)
        supportServiceAPI = new V2SupportServiceAPI.Builder()
            .messageSecurityProvider(new DummyMessageSecurityProvider())
            .trustedCertificateSource(new KeyStoreCertificateSource("src/test/resources/validation-truststore.jks", "jks", "foo123".toCharArray()))
            .build()
    }

    def "draw with unsigned pdf"() {
        given:
        InMemoryDocument document = new InMemoryDocument(new File(unsignedPdf).bytes)
        SignatureImageParameters imageParameters = createImageParameters("A signature")
        byte[] originalBytes = document.bytes

        when:
        byte[] result = PdfDrawing.draw(document, imageParameters)
        VerifyDocumentResponse response = supportServiceAPI.verifyDocument(testProfile1_for_test, new Document(
                referenceId: "123456", type: "application/pdf", name: "", data: result))

        then:
        result != null
        result.length > 0
        result != originalBytes
        !hasSignatureDictionaries(result)
        !response.verifies
        response.signatures != null
        response.signatures.signer.isEmpty()
    }

    def "draw with signed pdf"() {
        given:
        InMemoryDocument document = new InMemoryDocument(new File(signedPdf).bytes)
        SignatureImageParameters imageParameters = createImageParameters("A signature")
        byte[] originalBytes = document.bytes

        when:
        byte[] result = PdfDrawing.draw(document, imageParameters)
        VerifyDocumentResponse response = supportServiceAPI.verifyDocument(testProfile1_for_test, new Document(
                referenceId: "123456", type: "application/pdf", name: "", data: result))

        then:
        result != null
        result.length > 0
        result != originalBytes
        hasSignatureDictionaries(result)
        response.verifies
        response.signatures != null
        response.signatures.signer.size() == 1
    }

    private static SignatureImageParameters createImageParameters(String text) {
        SignatureImageParameters imageParameters = new SignatureImageParameters()

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters()
        fieldParameters.setPage(1)
        fieldParameters.setOriginX(20)
        fieldParameters.setOriginY(30)
        fieldParameters.setWidth(200)
        fieldParameters.setHeight(50)
        imageParameters.setFieldParameters(fieldParameters)

        SignatureImageTextParameters textParameters = new SignatureImageTextParameters()
        textParameters.setText(text)
        textParameters.setSignerTextPosition(SignerTextPosition.RIGHT)
        textParameters.setTextColor(Color.BLUE)
        textParameters.getFont().setSize(8)
        imageParameters.setTextParameters(textParameters)

        return imageParameters
    }

    private static boolean hasSignatureDictionaries(byte[] bytes) {
        try (PDDocument document = Loader.loadPDF(bytes)) {
            return !document.getSignatureDictionaries().isEmpty()
        }
    }

    private static SupportAPIProfile getProfile(Map profileData) {
        return new ObjectMapper().convertValue(profileData, SupportAPIProfile.class)
    }
}