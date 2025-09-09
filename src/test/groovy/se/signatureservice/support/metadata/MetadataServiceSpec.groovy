package se.signatureservice.support.metadata

import org.slf4j.Logger
import se.signatureservice.messages.metadata.ReducedMetadataImpl
import se.signatureservice.support.system.SupportAPIProfile
import spock.lang.Specification
import spock.lang.Unroll

class MetadataServiceSpec extends Specification {

    MetadataService service = new MetadataService(Mock(org.springframework.context.MessageSource))

    @Unroll
    def "Test setReqCertAttrFromMetaDataCustomCertAttr method"() {
        when:
        StringBuilder friendlyName = new StringBuilder()
        Map<String, Object> requestedAttributeMap = [:]
        SupportAPIProfile supportAPIProfile = new SupportAPIProfile()
        supportAPIProfile.metadataCustomCertAttribute = metadataCustomCertAttribute as Map<String, Map<String, Object>>
        service.setReqCertAttrFromMetaDataCustomCertAttr(supportAPIProfile, friendlyName, requestedAttributeMap, requestedAttribute)

        then:
        requestedAttributeMap.equals(expectedRequestedAttributeMap)
        friendlyName.toString() == expectedFriendlyName

        where:
        requestedAttribute                                                                                          | metadataCustomCertAttribute                                                                                                                                                    | expectedRequestedAttributeMap                                                                                                                         | expectedFriendlyName
        null                                                                                                        | ["givenName": ["samlAttributeName": "http://sambi.se/attributes/1/givenName"]]                                                                                                 | [:]                                                                                                                                                   | ""
        new ReducedMetadataImpl.RequestedAttribute("http://sambi.se/attributes/1/givenName", "falseGivenName", false) | ["givenName": ["samlAttributeName": "http://sambi.se/attributes/1/givenName", "certAttributeRef": "2.5.4.42", "certNameType": "TestCertNameType", "required": true]] | ["samlAttributeName": "http://sambi.se/attributes/1/givenName", "certAttributeRef": "2.5.4.42", "certNameType": "TestCertNameType", "required": true] | "givenName"
        new ReducedMetadataImpl.RequestedAttribute("http://sambi.se/attributes/1/givenName", "falseGivenName", false) | ["givenName": ["samlAttributeName": "http://sambi.se/attributes/1/givenName", "certAttributeRef": "2.5.4.42", "certNameType": null, "required": null]]                         | ["required": false, "samlAttributeName": "http://sambi.se/attributes/1/givenName", "certAttributeRef": "2.5.4.42", certNameType: "rdn"]               | "givenName"
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:1.2.752.29.6.2.1")                                        | ["serialNumber": ["samlAttributeName": ["urn:oid:1.2.752.29.4.13", "urn:oid:1.2.752.29.6.2.1", "urn:oid:1.2.752.201.3.1"], "certAttributeRef": "2.5.4.5", "required": "true"]] | ["samlAttributeName": "urn:oid:1.2.752.29.6.2.1", "certAttributeRef": "2.5.4.5", certNameType: "rdn", "required": true]                               | "serialNumber"
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3")                                                 | ["": ["samlAttributeName": "urn:oid:2.5.4.3", "certAttributeRef": "2.5.4.3"]]                                                                                                  | ["required": false, "samlAttributeName": "urn:oid:2.5.4.3", "certAttributeRef": "2.5.4.3", certNameType: "rdn"]                                       | "commonname"
    }

    @Unroll
    def "Test determineFriendlyName method"() {
        when:
        def result = service.determineFriendlyName(requestedAttributeType)

        then:
        result == expectedFriendlyName

        where:
        requestedAttributeType                                                          | expectedFriendlyName
        null                                                                            | null
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:1.3.3.7", "commonName", false) | "commonName"
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:1.3.3.7")                      | null
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3", "commonName", false) | "commonName"
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3")                      | "commonname"
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.4", "sn", false)         | "surname"
    }

    @Unroll
    def "Test setReqCertAttrFromMetaDataCustomCertAttr method when exceptions are thrown"() {
        setup:
        def logMock = Mock(Logger)
        service.msgLog = logMock
        StringBuilder friendlyName = new StringBuilder()
        Map<String, Object> requestedAttributeMap = [:]
        SupportAPIProfile supportAPIProfile = new SupportAPIProfile()
        supportAPIProfile.metadataCustomCertAttribute = metadataCustomCertAttribute as Map<String, Map<String, Object>>
        supportAPIProfile.relatedProfile = "TestProfile"

        when:
        service.setReqCertAttrFromMetaDataCustomCertAttr(supportAPIProfile, friendlyName, requestedAttributeMap, requestedAttribute)

        then:
        1 * logMock.error(_) >> { String message ->
            assert message.contains(errorMessage)
        }
        def error = thrown(se.signatureservice.support.api.v2.ServerErrorException)
        error.code == "10014"
        error.message.contains(errorMessage)

        where:
        requestedAttribute                                        | metadataCustomCertAttribute                                                                                | errorMessage
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["givenName": [:]]                                                                                         | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. Invalid value for 'samlAttributeName' under TestProfile.metadataCustomCertAttribute.givenName. It must be either a single string or a list of strings."
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["givenName": ""]                                                                                          | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. class java.lang.String cannot be cast to class java.util.Map (java.lang.String and java.util.Map are in module java.base of loader 'bootstrap')"
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["givenName": ["samlAttributeName": ""]]                                                                   | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. Invalid or empty value set in TestProfile.metadataCustomCertAttribute.givenName.samlAttributeName: . Please specify a valid String value."
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["givenName": ["samlAttributeName": ["urn:oid:2.5.4.3", "  "]]]                                            | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. Invalid or empty value in the list for TestProfile.metadataCustomCertAttribute.givenName.samlAttributeName: [urn:oid:2.5.4.3,   ]. Please specify valid String value(s)."
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["givenName": ["samlAttributeName": ["urn:oid:2.5.4.3", true]]]                                            | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. Invalid or empty value in the list for TestProfile.metadataCustomCertAttribute.givenName.samlAttributeName: [urn:oid:2.5.4.3, true]. Please specify valid String value(s)."
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["givenName": ["samlAttributeName": true]]                                                                 | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. Invalid value for 'samlAttributeName' under TestProfile.metadataCustomCertAttribute.givenName. It must be either a single string or a list of strings."
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["givenName": ["samlAttributeName": "urn:oid:2.5.4.3"]]                                                    | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. Invalid or missing 'certAttributeRef' value in: TestProfile.metadataCustomCertAttribute.givenName. Please specify a valid String value."
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["givenName": ["samlAttributeName": "urn:oid:2.5.4.3", "certAttributeRef": true]]                          | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. Invalid or missing 'certAttributeRef' value in: TestProfile.metadataCustomCertAttribute.givenName. Please specify a valid String value."
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["givenName": ["samlAttributeName": "urn:oid:2.5.4.3", "certAttributeRef": "2.5.4.3", certNameType: true]] | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. Invalid or missing 'certNameType' value in TestProfile.metadataCustomCertAttribute.givenName. Please specify a valid String value."
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["givenName": ["samlAttributeName": "urn:oid:2.5.4.3", "certAttributeRef": "2.5.4.3", required: ["true"]]] | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. Invalid or missing 'required' value in TestProfile.metadataCustomCertAttribute.givenName. Please specify a valid Boolean value."
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3") | ["": ["samlAttributeName": "urn:oid:2.5.4.3", "certAttributeRef": "1.3.3.7"]]                              | "Failed to automatically parse requestedCertAttributes from metadata using metadataCustomCertAttribute configuration. Unable to append friendlyName. Empty or invalid value for friendlyName key in TestProfile.metadataCustomCertAttribute: . Please specify a valid String value. No friendlyName match found for TestProfile.metadataCustomCertAttribute..certAttributeRef: 1.3.3.7."
    }

    @Unroll
    def "Test setReqCertAttrFromMetaData method"() {
        when:
        StringBuilder friendlyName = new StringBuilder()
        Map<String, Object> requestedAttributeMap = [:]
        service.setReqCertAttrFromMetaData(friendlyName, requestedAttributeMap, requestedAttribute)

        then:
        requestedAttributeMap.equals(expectedRequestedAttributeMap)
        friendlyName.toString() == expectedFriendlyName

        where:
        requestedAttribute                                                                                  | expectedRequestedAttributeMap                                                                                          | expectedFriendlyName
        null                                                                                                | [:]                                                                                                                    | ""
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3", "commonName", true)   | ["samlAttributeName": "urn:oid:2.5.4.3", "certAttributeRef": "2.5.4.3", certNameType: "rdn", "required": true]         | "commonName"
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:2.5.4.3")                       | ["samlAttributeName": "urn:oid:2.5.4.3", "certAttributeRef": "2.5.4.3", certNameType: "rdn", "required": false]        | "commonname"
        new ReducedMetadataImpl.RequestedAttribute("urn:oid:1.2.752.29.4.13", "prid", true) | ["samlAttributeName": "urn:oid:1.2.752.29.4.13", "certAttributeRef": "2.5.4.5", certNameType: "rdn", "required": true] | "serialnumber"
    }
}
