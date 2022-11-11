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
