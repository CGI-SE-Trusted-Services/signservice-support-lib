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
package se.signatureservice.support.api

import se.signatureservice.support.api.v2.Attribute
import spock.lang.Specification
import spock.lang.Unroll

class AvailableSignatureAttributesSpec extends Specification {
    @Unroll
    def "should return #expectedResult when signatureAttributes is #signatureAttributes and attributeKey is #attributeKey"() {
        when:
        String result = AvailableSignatureAttributes.getAttributeValue(signatureAttributes, attributeKey)

        then:
        result == expectedResult

        where:
        signatureAttributes                                                  | attributeKey          || expectedResult
        [new Attribute(key: 'AUTHCONTEXTCLASSREF', value: 'SomeValue')]      | 'AUTHCONTEXTCLASSREF' || 'SomeValue'
        [new Attribute(key: 'AUTHCONTEXTCLASSREF', value: 'SomeValue')]      | 'AUTHCONTEXTCLASSREF' || 'SomeValue'
        [new Attribute(key: 'authcontextclassref', value: 'LowerCaseValue')] | 'AUTHCONTEXTCLASSREF' || 'LowerCaseValue'
        [new Attribute(key: 'DifferentKey', value: 'DifferentValue')]        | 'AUTHCONTEXTCLASSREF' || null
        null                                                                 | 'AUTHCONTEXTCLASSREF' || null
        [new Attribute(key: 'AUTHCONTEXTCLASSREF', value: 'SomeValue')]      | null                  || null
        [new Attribute(key: 'authcontextclassref', value: 'LowerCaseValue'),
         new Attribute(key: 'AnotherKey', value: 'AnotherValue')]            | 'ANOTHERKEY'          || 'AnotherValue'
    }
}
