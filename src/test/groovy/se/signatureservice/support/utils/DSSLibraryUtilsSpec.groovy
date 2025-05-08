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
package se.signatureservice.support.utils

import eu.europa.esig.dss.enumerations.MimeTypeEnum
import eu.europa.esig.dss.model.InMemoryDocument
import se.signatureservice.support.api.v2.AbstractDocument
import spock.lang.Specification

import java.security.KeyStore

class DSSLibraryUtilsSpec extends Specification {
    def "test createDSSDocument"(){
        setup:
        AbstractDocument document = new AbstractDocument(
                name: "testdocument.bin",
                type: "application/octet-stream",
                data: [1,2,3,4,5,6,5,4,3,2,1] as byte[]
        )

        when:
        InMemoryDocument dssDocument = DSSLibraryUtils.createDSSDocument(document) as InMemoryDocument

        then:
        dssDocument != null
        dssDocument.name == "testdocument.bin"
        dssDocument.mimeType == MimeTypeEnum.BINARY
        dssDocument.bytes == [1,2,3,4,5,6,5,4,3,2,1] as byte[]
    }

    def "test createDSSDocument from resource"(){
        when:
        InMemoryDocument dssDocument = DSSLibraryUtils.createDSSDocument("/truststore.jks") as InMemoryDocument

        then:
        dssDocument != null
        dssDocument.name == "truststore.jks"
        KeyStore trustStore = KeyStore.getInstance("JKS")
        trustStore.load(new ByteArrayInputStream(dssDocument.bytes), "foo123".toCharArray())
        trustStore.containsAlias("devsigner")
    }

    def "test createDSSDocument from filesystem"(){
        when:
        InMemoryDocument dssDocument = DSSLibraryUtils.createDSSDocument("src/test/resources/truststore.jks") as InMemoryDocument

        then:
        dssDocument != null
        dssDocument.name == "truststore.jks"
        KeyStore trustStore = KeyStore.getInstance("JKS")
        trustStore.load(new ByteArrayInputStream(dssDocument.bytes), "foo123".toCharArray())
        trustStore.containsAlias("devsigner")
    }
}
