package se.signatureservice.support.metadata


import spock.lang.Specification
import spock.lang.Unroll

/**
 * Unit tests for {@link se.signatureservice.support.metadata.DefaultUserIdAttributeMappingValues}.
 *
 * @author Filip Wessman 2023-11-17
 */
class DefaultUserIdAttributeMappingValuesSpec extends Specification {

    @Unroll
    def "findMatches should return #expectedSize matching values for #inputValues with profile constants #profileConstants"() {
        when:
        List<String> matches = DefaultUserIdAttributeMappingValues.findMatches(inputValues, profileConstants)

        then:
        matches.size() == expectedSize
        matches.containsAll(expectedMatches)

        where:
        inputValues                                                                                                | profileConstants                                     | expectedSize | expectedMatches
        ["urn:oid:1.2.752.29.4.13 ", "non-matching-value ", "http://sambi.se/attributes/1/personalIdentityNumber"] | null                                                 | 2            | ["urn:oid:1.2.752.29.4.13", "http://sambi.se/attributes/1/personalIdentityNumber"]
        ["urn:oid:1.2.752.29.4.13", null, "urn:orgAffiliation"]                                                    | null                                                 | 2            | ["urn:oid:1.2.752.29.4.13", "urn:orgAffiliation"]
        [null]                                                                                                     | null                                                 | 0            | []
        ["  "]                                                                                                     | null                                                 | 0            | []
        ["non-matching-value-1", "non-matching-value-2"]                                                           | null                                                 | 0            | []
        [" ", "urn:oid:1.2.752.201.3.4 ", ""]                                                                      | null                                                 | 1            | ["urn:oid:1.2.752.201.3.4"]
        ["additional-constant-1", "urn:oid:1.2.752.29.4.13"]                                                       | [" additional-constant-1", " additional-constant-2"] | 1            | ["additional-constant-1"]
        ["additional-constant-1", "urn:oid:1.2.752.29.4.13"]                                                       | [" additional-constant-1", null]                     | 1            | ["additional-constant-1"]
    }
}
