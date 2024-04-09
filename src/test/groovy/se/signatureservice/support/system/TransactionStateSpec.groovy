package se.signatureservice.support.system

import se.signatureservice.support.api.AvailableSignatureAttributes
import se.signatureservice.support.api.v2.*
import se.signatureservice.support.utils.TestUtils
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import java.text.SimpleDateFormat

/**
 * Created by agerbergt on 2017-05-16.
 */
class TransactionStateSpec extends Specification {
    @Shared List<Attribute> testAttributes = []
    @Shared List<Object> testDocuments1 = []
    @Shared List<Object> testDocuments2 = []
    @Shared List<Object> testDocuments3 = []
    @Shared Map<String, Date> signingTimes1 = [:]
    @Shared Map<String, Date> signingTimes2 = [:]
    @Shared Map<String, Date> signingTimes3 = [:]
    @Shared List<Attribute> testSignatureAttributes = []
    @Shared Map<String, List<Attribute>> testDocumentSignatureAttributes = [:]

    def setupSpec() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")

        testAttributes.add(new Attribute(key: "name", value: "Testare Testsson"))
        testAttributes.add(new Attribute(key: "email", value: "testare@testsson.se"))
        testAttributes.add(new Attribute(key: "telephone", value: "+467012345678"))

        testDocuments1.add(new DocumentRef(referenceId: "123456"))
        testDocuments1.add(new DocumentRef(referenceId: "654321"))
        testDocuments1.add(new DocumentRef(referenceId: "ref-abc-åäö-123-xyz-321"))
        signingTimes1 = [
                "123456"                 : dateFormat.parse("2017-06-08 13:37:00"),
                "654321"                 : dateFormat.parse("2017-05-04 08:42:00"),
                "ref-abc-åäö-123-xyz-321": dateFormat.parse("2017-04-02 06:25:00")
        ]

        testDocuments2.add(new DocumentSigningRequest(referenceId: "456789", type: "pdf", name: "test1.pdf", data: TestUtils.genRandomByteArray(5000)))
        testDocuments2.add(new DocumentSigningRequest(referenceId: "987654", type: "xml", name: "test2.xml", data: TestUtils.genRandomByteArray(2000)))
        testDocuments2.add(new DocumentSigningRequest(referenceId: "507f62cf-4a71-4191-8dbf-3690f8257728", type: "docx", name: "test3.docx", data: TestUtils.genRandomByteArray(10000)))
        signingTimes2 = [
                "456789"                              : dateFormat.parse("2017-01-08 10:22:00"),
                "987654"                              : dateFormat.parse("2017-02-04 09:36:00"),
                "507f62cf-4a71-4191-8dbf-3690f8257728": dateFormat.parse("2017-03-02 05:10:00")
        ]

        testDocuments3.add(new DocumentRef(referenceId: "123456"))
        testDocuments3.add(new DocumentSigningRequest(referenceId: "456789", type: "pdf", name: "test1.pdf", data: TestUtils.genRandomByteArray(5000)))
        testDocuments3.add(new DocumentRef(referenceId: "654321"))
        testDocuments3.add(new DocumentSigningRequest(referenceId: "987654", type: "xml", name: "test2.xml", data: TestUtils.genRandomByteArray(2000)))
        testDocuments3.add(new DocumentRef(referenceId: "ref-abc-åäö-123-xyz-321"))
        testDocuments3.add(new DocumentSigningRequest(referenceId: "507f62cf-4a71-4191-8dbf-3690f8257728", type: "docx", name: "test3.docx", data: TestUtils.genRandomByteArray(10000)))
        signingTimes3 = [
                "123456"                              : dateFormat.parse("2017-06-08 13:37:00"),
                "456789"                              : dateFormat.parse("2017-01-08 10:22:00"),
                "654321"                              : dateFormat.parse("2017-05-04 08:42:00"),
                "987654"                              : dateFormat.parse("2017-02-04 09:36:00"),
                "ref-abc-åäö-123-xyz-321"             : dateFormat.parse("2017-04-02 06:25:00"),
                "507f62cf-4a71-4191-8dbf-3690f8257728": dateFormat.parse("2017-03-02 05:10:00")
        ]

        testSignatureAttributes.add(new Attribute(key: AvailableSignatureAttributes.ATTRIBUTE_PREFERRED_LANG, value: "SV"))
        testSignatureAttributes.add(new Attribute(key: AvailableSignatureAttributes.VISIBLE_SIGNATURE_PAGE, value: "5"))
        testDocumentSignatureAttributes.put(testDocuments1.get(0)["referenceId"] as String, testSignatureAttributes)
        testDocumentSignatureAttributes.put(testDocuments1.get(1)["referenceId"] as String, testSignatureAttributes)
    }

    @Unroll
    def "test serialization"() {
        given:
        User user = new User(userId: userId, userAttributes: userAttributes)
        DocumentRequests documentRequests = new DocumentRequests(documents: documents)
        TransactionState state = new TransactionState(
                transactionId: transactionId,
                profile: profile,
                signMessage: signMessage,
                authenticationServiceId: authenticationServiceId,
                user: user,
                documents: documentRequests,
                signingTime: signingTime,
                transactionStart: 123456,
                signatureAttributes: signatureAttributes,
                documentSignatureAttributes: documentSignatureAttributes
        )

        when:
        TransactionState restoredState = TestUtils.genSerializedObjectClone(state) as TransactionState

        then:
        TransactionState.serialVersionUID == 1L
        restoredState != null
        restoredState.transactionId == state.transactionId
        restoredState.profile == state.profile
        restoredState.signMessage == state.signMessage
        restoredState.authenticationServiceId == state.authenticationServiceId
        restoredState.user != null
        restoredState.user.userId == state.user.userId
        restoredState.transactionStart == 123456

        if (state.user.userAttributes != null) {
            state.user.userAttributes.each {
                String attributeKey = it.key
                String attributeValue = it.value
                Attribute restoredAttribute = restoredState.user.userAttributes.find { it.key == attributeKey }
                assert restoredAttribute != null
                restoredAttribute.value == attributeValue
            }
        }

        if (state.documents.documents == null) {
            assert restoredState.documents.documents == null
        } else if (state.documents.documents.size() == 0) {
            assert restoredState.documents.documents.size() == 0
        } else {
            state.documents.documents.each {
                assert it instanceof DocumentRef || it instanceof DocumentSigningRequest
                if (it instanceof DocumentRef) {
                    DocumentRef documentRef = it
                    DocumentRef restoredDocumentRef = restoredState.documents.documents.find {
                        it instanceof DocumentRef &&
                                it.referenceId == documentRef.referenceId
                    }
                    assert restoredDocumentRef != null
                } else if (it instanceof DocumentSigningRequest) {
                    DocumentSigningRequest documentSigningRequest = it
                    DocumentSigningRequest restoredDocumentSigningRequest = restoredState.documents.documents.find {
                        it instanceof DocumentSigningRequest &&
                                it.referenceId == documentSigningRequest.referenceId &&
                                it.name == documentSigningRequest.name &&
                                it.type == documentSigningRequest.type &&
                                it.data == documentSigningRequest.data
                    }
                    assert restoredDocumentSigningRequest != null
                }
            }
        }

        if (state.signingTime != null) {
            assert restoredState.signingTime != null

            state.signingTime.each { key, value ->
                assert restoredState.signingTime.get(key).compareTo(value) == 0
            }
        }

        if (state.signatureAttributes != null) {
            state.signatureAttributes.each {
                String attributeKey = it.key
                String attributeValue = it.value
                Attribute restoredAttributeValue = restoredState.signatureAttributes.find { it.key == attributeKey } as Attribute
                assert restoredAttributeValue != null
                restoredAttributeValue.value == attributeValue
            }
        }

        if (state.documentSignatureAttributes != null) {
            state.documentSignatureAttributes.each { stateIt ->
                def restoredDocSignAttr = restoredState.documentSignatureAttributes.find { restoredIt -> stateIt.key == restoredIt.key }
                assert restoredDocSignAttr != null
                stateIt.value.each {
                    String attributeKey = it.key
                    String attributeValue = it.value
                    Attribute restoredAttributeValue = restoredDocSignAttr.value.find { it.key == attributeKey } as Attribute
                    assert restoredAttributeValue != null
                    restoredAttributeValue.value == attributeValue
                }
            }
        }

        where:
        userId        | userAttributes | documents      | signingTime   | transactionId                          | profile          | signMessage       | authenticationServiceId                 | signatureAttributes     | documentSignatureAttributes
        "testuser"    | null           | null           | null          | "abcdefghijklmnopqrstuvxyzåäöABCDEFGH" | "testprofile"    | "test message"    | "testserviceid"                         | null                    | testDocumentSignatureAttributes
        "anotheruser" | testAttributes | null           | null          | "f79e111c-6405-497f-862c-66ed41391790" | "anotherprofile" | "another message" | "another serviceid"                     | testSignatureAttributes | null
        "0101010101"  | testAttributes | testDocuments1 | signingTimes1 | "07885e1d-6b76-4ada-a32b-e4d70a50dda2" | null             | "message 123"     | "123456789"                             | null                    | testDocumentSignatureAttributes
        "yet-a-user"  | testAttributes | testDocuments2 | signingTimes2 | "2c05518a-d7e7-4d87-94d5-1aa77afa8851" | "sec-prof-007"   | "ÅÄÖ åäö &?!"     | "http://some.service.com/serviceid?123" | testSignatureAttributes | testDocumentSignatureAttributes
        "moreuser123" | testAttributes | testDocuments3 | signingTimes3 | "4970a3c8-831e-411b-851c-a7696d1ca736" | "abcABC123123"   | "Sign 100%?()"    | "0205b1a2-94af-45b8-90cb-cb54fb30c76f"  | testSignatureAttributes | testDocumentSignatureAttributes
    }
}
