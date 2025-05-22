package se.signatureservice.support.utils

import spock.lang.Specification

/*
 * test for AuthnContextClassRefUtils
 */
class AuthnContextClassRefUtilsSpec extends Specification {

    def "test equalOrHigherLoa" () {

        expect:
        AuthnContextClassRefUtils.equalOrHigherLoa("") == [""]
        AuthnContextClassRefUtils.equalOrHigherLoa("ref") == ["ref"]
        AuthnContextClassRefUtils.equalOrHigherLoa("http://id.swedenconnect.se/loa/1.0/loa2-nonresident") == ["http://id.swedenconnect.se/loa/1.0/loa2-nonresident", "http://id.swedenconnect.se/loa/1.0/loa3-nonresident", "http://id.swedenconnect.se/loa/1.0/loa4-nonresident"]
        AuthnContextClassRefUtils.equalOrHigherLoa("http://id.elegnamnden.se/loa/1.0/loa3") == ["http://id.elegnamnden.se/loa/1.0/loa3", "http://id.elegnamnden.se/loa/1.0/loa4"]
    }

    def "test equalOrHigherLoas" () {

        expect:
        AuthnContextClassRefUtils.equalOrHigherLoas([]) == []
        AuthnContextClassRefUtils.equalOrHigherLoas(["ref"]) == ["ref"]
        AuthnContextClassRefUtils.equalOrHigherLoas(["http://id.elegnamnden.se/loa/1.0/loa3", "http://id.elegnamnden.se/loa/1.0/loa4"]) == ["http://id.elegnamnden.se/loa/1.0/loa3", "http://id.elegnamnden.se/loa/1.0/loa4"]
        AuthnContextClassRefUtils.equalOrHigherLoas([
                "ref",
                "http://id.swedenconnect.se/loa/1.0/loa2-nonresident",
                "http://id.elegnamnden.se/loa/1.0/loa3",
                "http://id.elegnamnden.se/loa/1.0/eidas-high"]
        ) == ["ref",
                 "http://id.swedenconnect.se/loa/1.0/loa2-nonresident",
                 "http://id.swedenconnect.se/loa/1.0/loa3-nonresident",
                 "http://id.swedenconnect.se/loa/1.0/loa4-nonresident",
                 "http://id.elegnamnden.se/loa/1.0/loa3",
                 "http://id.elegnamnden.se/loa/1.0/loa4",
                 "http://id.elegnamnden.se/loa/1.0/eidas-high"
                ]
    }
}
