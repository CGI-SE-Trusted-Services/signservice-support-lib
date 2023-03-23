/************************************************************************
 *                                                                       *
 *  Signservice Support Lib                                              *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  (LGPL-3.0-or-later)                                                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.utils

import spock.lang.Specification

class SupportLibraryUtilsSpec extends Specification {
    def "test generateTransactionId"(){
        when:
        List<String> transactionIds = []
        for(int i=0;i<1000;i++){
            transactionIds.add(SupportLibraryUtils.generateTransactionId())
        }

        then:
        transactionIds.each { String rs ->
            assert rs != null
            assert rs.length() >= 32
            assert transactionIds.findAll { it == rs }.size() == 1
        }
    }

    def "test generateReferenceId"() {
        when:
        List<String> referenceIds = []
        for(int i=0;i<1000;i++){
            referenceIds.add(SupportLibraryUtils.generateReferenceId())
        }

        then:
        referenceIds.each { String ri ->
            assert ri != null
            assert ri.length() >= 32
            assert referenceIds.findAll { it == ri }.size() == 1
        }
    }
}
