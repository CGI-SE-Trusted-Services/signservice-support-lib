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
package se.signatureservice.support.system

import org.springframework.context.support.StaticMessageSource
import se.signatureservice.support.api.ErrorCode
import se.signatureservice.support.api.v2.BaseAPIException
import spock.lang.Specification
import spock.lang.Unroll

class ErrorCodeSpec extends Specification {

    @Unroll
    def "test toException for error code #errorCode.errorCode"() {
        when:
        BaseAPIException exception = errorCode.toException("test")

        then:
        exception.class.name == expectedException
        exception.detailMessage == "test"
        exception.code == expectedCode

        where:
        errorCode                            | expectedException                                         | expectedCode | expectedMessageCode
        ErrorCode.MISSING_CONFIGURATION      | "se.signatureservice.support.api.v2.ServerErrorException" | "10001"      | "error.missing.configuration"
        ErrorCode.INVALID_CONFIGURATION      | "se.signatureservice.support.api.v2.ServerErrorException" | "10002"      | "error.invalid.configuration"
        ErrorCode.UNSUPPORTED_ALGORITHM      | "se.signatureservice.support.api.v2.ClientErrorException" | "10003"      | "error.unsupported.algorithm"
        ErrorCode.INVALID_DIGEST_SIZE        | "se.signatureservice.support.api.v2.ServerErrorException" | "10004"      | "error.invalid.digest.size"
        ErrorCode.INVALID_CERTIFICATE_CHAIN  | "se.signatureservice.support.api.v2.ServerErrorException" | "10005"      | "error.invalid.certificate.chain"
        ErrorCode.UNSUPPORTED_SIGNATURE_TYPE | "se.signatureservice.support.api.v2.ClientErrorException" | "10006"      | "error.unsupported.signature.type"
        ErrorCode.INVALID_PROFILE            | "se.signatureservice.support.api.v2.ClientErrorException" | "10007"      | "error.invalid.profile"
        ErrorCode.METADATA_ERROR             | "se.signatureservice.support.api.v2.ServerErrorException" | "10008"      | "error.metadata"
        ErrorCode.UNAUTHORIZED_CONSUMER      | "se.signatureservice.support.api.v2.ClientErrorException" | "10009"      | "error.unauthorized.consumer"
        ErrorCode.UNSUPPORTED_TRANSACTION_ID | "se.signatureservice.support.api.v2.ClientErrorException" | "10010"      | "error.unsupported.transactionid"
        ErrorCode.UNKNOWN_TRANSACTION        | "se.signatureservice.support.api.v2.ClientErrorException" | "10011"      | "error.unknown.transaction"
        ErrorCode.SIGN_RESPONSE_FAILED       | "se.signatureservice.support.api.v2.ServerErrorException" | "10012"      | "error.sign.response.failed"
        ErrorCode.UNSUPPORTED_OPERATION      | "se.signatureservice.support.api.v2.ClientErrorException" | "10013"      | "error.unsupported.operation"
        ErrorCode.INTERNAL_ERROR             | "se.signatureservice.support.api.v2.ServerErrorException" | "10014"      | "error.internal"
        ErrorCode.UNAUTHORIZED_AUTH_SERVICE  | "se.signatureservice.support.api.v2.ClientErrorException" | "10015"      | "error.unauthorized.auth.service"
        ErrorCode.INVALID_DOCUMENT           | "se.signatureservice.support.api.v2.ClientErrorException" | "10016"      | "error.invalid.document"
        ErrorCode.INVALID_MIMETYPE           | "se.signatureservice.support.api.v2.ClientErrorException" | "10017"      | "error.invalid.mimetype"
        ErrorCode.INVALID_SIGN_RESPONSE      | "se.signatureservice.support.api.v2.ClientErrorException" | "10018"      | "error.invalid.sign.response"
        ErrorCode.SIGN_REQUEST_FAILED        | "se.signatureservice.support.api.v2.ServerErrorException" | "10019"      | "error.sign.request.failed"
        ErrorCode.VERIFY_DOCUMENT_FAILED     | "se.signatureservice.support.api.v2.ServerErrorException" | "10020"      | "error.verify.document.failed"
    }

    @Unroll
    def "test toException with preferredLanguage #language"() {
        setup:
        def messageSource = new StaticMessageSource()
        messageSource.addMessage "error.invalid.profile", new Locale("en"), "Invalid profile"
        messageSource.addMessage "error.invalid.profile", new Locale("sv"), "Ogiltig profil"

        when:
        ErrorCode.setErrorLanguage(language)
        BaseAPIException exception = errorCode.toException("test", messageSource)

        then:
        exception.messages.message.first().lang == expectedLanguage
        exception.messages.message.first().text == expectedText

        where:
        errorCode                 | language | expectedLanguage | expectedText
        ErrorCode.INVALID_PROFILE | "en"     | "en"             | "Invalid profile"
        ErrorCode.INVALID_PROFILE | "sv"     | "sv"             | "Ogiltig profil"
    }
}
