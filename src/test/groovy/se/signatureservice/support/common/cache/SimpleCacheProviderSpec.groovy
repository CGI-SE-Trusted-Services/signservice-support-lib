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
package se.signatureservice.support.common.cache

import se.signatureservice.configuration.common.InvalidArgumentException
import se.signatureservice.configuration.common.cache.MetaData
import spock.lang.Specification
import spock.lang.Subject
import spock.lang.Unroll

/**
 * Unit tests for SimpleCacheProvider.
 */
class SimpleCacheProviderSpec extends Specification {

    @Subject
    SimpleCacheProvider cacheProvider = new SimpleCacheProvider()

    def "set and get a string value"() {
        when:
        cacheProvider.set("testKey", "testValue")

        then:
        cacheProvider.get("testKey") == "testValue"
    }

    def "get returns null for non-existent key"() {
        expect:
        cacheProvider.get("nonExistentKey") == null
    }

    def "set and get a binary value"() {
        given:
        byte[] data = [1, 2, 3, 4, 5] as byte[]

        when:
        cacheProvider.set("binaryKey", data)

        then:
        cacheProvider.getBinary("binaryKey") == data
    }

    @Unroll
    def "set with contextId should correctly store and retrieve values"() {
        when:
        cacheProvider.set(contextId, key, value)

        then:
        cacheProvider.get(contextId, key) == value

        where:
        contextId  | key      | value
        "ctx1"     | "key1"   | "value1"
        "ctx2"     | "key2"   | "value2"
    }

    def "deleting a key removes it from cache"() {
        given:
        cacheProvider.set("deleteKey", "toBeDeleted")

        when:
        cacheProvider.delete("deleteKey")

        then:
        cacheProvider.get("deleteKey") == null
    }

    def "should throw InvalidArgumentException for type mismatch"() {
        given:
        cacheProvider.set("byteKey", "testBytes".getBytes())

        when:
        cacheProvider.get("byteKey")

        then:
        thrown(InvalidArgumentException)
    }

    def "set with expiration removes entry after TTL"() {
        given:
        MetaData metaData = new MetaData()
        metaData.setTimeToLive(1) // TTL = 1 second

        when:
        cacheProvider.set("expiringKey", "temporaryValue", metaData)
        Thread.sleep(1500) // Wait for expiration

        then:
        cacheProvider.get("expiringKey") == null
    }

    def "buildContextKey correctly formats keys"() {
        expect:
        cacheProvider.buildContextKey("ctx1", "key1") == "ctx1;key1"
    }

    def "should initialize with empty properties"() {
        when:
        cacheProvider.init(new Properties())

        then:
        noExceptionThrown()
    }
}

