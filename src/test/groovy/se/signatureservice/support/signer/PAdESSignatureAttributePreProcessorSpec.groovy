package se.signatureservice.support.signer

import se.signatureservice.support.api.v2.Attribute
import se.signatureservice.support.api.v2.DocumentSigningRequest
import spock.lang.Shared
import spock.lang.Specification

import static se.signatureservice.support.api.AvailableSignatureAttributes.*

class PAdESSignatureAttributePreProcessorSpec extends Specification {
    @Shared
    PAdESSignatureAttributePreProcessor preProcessor

    def setupSpec(){
        preProcessor = new PAdESSignatureAttributePreProcessor()
    }

    def "verify doPreProcess"(){
        setup:
        DocumentSigningRequest document1 = new DocumentSigningRequest(referenceId: "123456", type: "application/pdf", name: "testdocument.pdf", data: new File("src/test/resources/testdocument.pdf").bytes)
        DocumentSigningRequest document2 = new DocumentSigningRequest(referenceId: "234567", type: "text/xml", name: "testdocument-multipage.pdf", data: new File("src/test/resources/testdocument-multipage.pdf").bytes)
        List<Attribute> signatureAttributes = [
                new Attribute(key: VISIBLE_SIGNATURE_POSITION_X, value: "50"),
                new Attribute(key: VISIBLE_SIGNATURE_POSITION_Y, value: "50"),
                new Attribute(key: VISIBLE_SIGNATURE_PAGE, value: "100000")
        ]

        when:
        List<Attribute> preProcessedAttributes1 = preProcessor.preProcess(signatureAttributes, document1)
        List<Attribute> preProcessedAttributes2 = preProcessor.preProcess(signatureAttributes, document2)

        then:
        preProcessedAttributes1 != null
        signatureAttributes != preProcessedAttributes1
        preProcessedAttributes1.find { it.key == VISIBLE_SIGNATURE_PAGE && it.value == "1" } != null
        preProcessedAttributes2 != null
        signatureAttributes != preProcessedAttributes2
        preProcessedAttributes2.find { it.key == VISIBLE_SIGNATURE_PAGE && it.value == "6" } != null
    }
}
