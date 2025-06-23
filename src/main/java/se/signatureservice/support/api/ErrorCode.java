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
package se.signatureservice.support.api;

import org.springframework.context.MessageSource;
import se.signatureservice.support.api.v2.BaseAPIException;
import se.signatureservice.support.api.v2.ClientErrorException;
import se.signatureservice.support.api.v2.Message;
import se.signatureservice.support.api.v2.ServerErrorException;

import java.lang.reflect.Constructor;
import java.lang.reflect.UndeclaredThrowableException;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.Objects;

/**
 * Error code definitions to be used when returning errors when interacting
 * with the Signature Support Service WS API.
 *
 * @author Tobias Agerberg
 */
public enum ErrorCode {
    MISSING_CONFIGURATION               ("10001", "error.missing.configuration", "Required configuration is missing", ServerErrorException.class),
    INVALID_CONFIGURATION               ("10002", "error.invalid.configuration", "Invalid configuration", ServerErrorException.class),
    UNSUPPORTED_ALGORITHM               ("10003", "error.unsupported.algorithm", "Unsupported algorithm", ClientErrorException.class),
    INVALID_DIGEST_SIZE                 ("10004", "error.invalid.digest.size", "Invalid digest size", ServerErrorException.class),
    INVALID_CERTIFICATE_CHAIN           ("10005", "error.invalid.certificate.chain", "Signature certificate chain is missing or invalid", ServerErrorException.class),
    UNSUPPORTED_SIGNATURE_TYPE          ("10006", "error.unsupported.signature.type", "Signature type is not supported", ClientErrorException.class),
    INVALID_PROFILE                     ("10007", "error.invalid.profile", "Invalid profile", ClientErrorException.class),
    METADATA_ERROR                      ("10008", "error.metadata", "Error while accessing or processing metadata", ServerErrorException.class),
    UNAUTHORIZED_CONSUMER               ("10009", "error.unauthorized.consumer", "Unauthorized consumer", ClientErrorException.class),
    UNSUPPORTED_TRANSACTION_ID          ("10010", "error.unsupported.transactionid", "Transaction ID is invalid or not supported.", ClientErrorException.class),
    UNKNOWN_TRANSACTION                 ("10011", "error.unknown.transaction", "Unknown transaction", ClientErrorException.class),
    SIGN_RESPONSE_FAILED                ("10012", "error.sign.response.failed", "Error while processing signature response", ServerErrorException.class),
    UNSUPPORTED_OPERATION               ("10013", "error.unsupported.operation", "Unsupported operation requested", ClientErrorException.class),
    INTERNAL_ERROR                      ("10014", "error.internal", "Internal error while processing transaction", ServerErrorException.class),
    UNAUTHORIZED_AUTH_SERVICE           ("10015", "error.unauthorized.auth.service", "Unauthorized authentication service", ClientErrorException.class),
    INVALID_DOCUMENT                    ("10016", "error.invalid.document", "Document to be signed is invalid, missing or corrupt", ClientErrorException.class),
    INVALID_MIMETYPE                    ("10017", "error.invalid.mimetype", "Invalid mime type. See documentation for valid mime types", ClientErrorException.class),
    INVALID_SIGN_RESPONSE               ("10018", "error.invalid.sign.response", "SignResponse is missing, invalid or corrupt", ClientErrorException.class),
    SIGN_REQUEST_FAILED                 ("10019", "error.sign.request.failed", "Error while generating signature request", ServerErrorException.class),
    VERIFY_DOCUMENT_FAILED              ("10020", "error.verify.document.failed", "Error while verifying document", ServerErrorException.class),
    INVALID_SIGN_TASK                   ("10021", "error.invalid.sign.task", "Invalid sign task", ClientErrorException.class),
    MESSAGE_PROCESSING_ERROR            ("10022", "error.message.processing", "Message processing error", ServerErrorException.class),
    INVALID_VISIBLE_SIGNATURE_ATTRIBUTE ("10023", "error.invalid.visible.signature.attribute", "Error while generating visible signature", ClientErrorException.class),
    INVALID_AUTH_CONTEXT_CLASS_REF      ("10024", "error.invalid.authcontextclassref", "The provided AuthnContextClassRef is invalid or does not match the allowed list", ClientErrorException.class),
    INVALID_SIGNATURE_ATTRIBUTE         ("10025", "error.invalid.signature.attribute", "Invalid signature attribute provided", ClientErrorException.class),
    INVALID_PARAMETER_VALUE             ("10026", "error.invalid.parameter.value", "Invalid value for parameter", ClientErrorException.class);

    private final String errorCode;
    private final String messageCode;
    private final String defaultMessage;
    private final Class<?> exceptionClass;

    private volatile static Locale errorLocale = Locale.getDefault();

    ErrorCode(final String errorCode, final String messageCode, final String defaultMessage, Class<?> exceptionClass) {
        this.errorCode = errorCode;
        this.messageCode = messageCode;
        this.defaultMessage = defaultMessage;
        this.exceptionClass = exceptionClass;
    }

    /**
     * Generate an exception based on the error. Default error message is used.
     * @param detailMessage Detail message to be included in the exception
     * @return ServerErrorException or ClientErrorException based on the error
     */
    public BaseAPIException toException(String detailMessage) {
        return generateException(exceptionClass, errorCode, "en", defaultMessage, detailMessage);
    }

    /**
     * Generate an exception based on the error.
     * @param detailMessage Detail message to be included in the exception
     * @param messageSource Message source to retrieve error message for the default system locale
     * @return ServerErrorException or ClientErrorException based on the error
     */
    public BaseAPIException toException(String detailMessage, MessageSource messageSource) {
        String text = messageSource != null ? messageSource.getMessage(messageCode, null, defaultMessage, errorLocale) : defaultMessage;
        return generateException(exceptionClass, errorCode, (!Objects.equals(text, defaultMessage) ? errorLocale.getLanguage() : "en"), text, detailMessage);
    }

    /**
     * Generate an exception based on the error. Detail message is gathered from given
     * root cause exception.
     * @param cause Exception that caused the error to be presented to the calling entity
     * @param messageSource Message source to retrieve error message for the default system locale
     * @return ServerErrorException or ClientErrorException based on the error
     */
    public BaseAPIException toException(Exception cause, MessageSource messageSource) {
        String text = messageSource != null ? messageSource.getMessage(messageCode, null, defaultMessage, errorLocale) : defaultMessage;
        String detailMessage = cause.getMessage();
        if(cause instanceof UndeclaredThrowableException){
            detailMessage = ((UndeclaredThrowableException) cause).getUndeclaredThrowable().getMessage();
        } else if(detailMessage == null && cause.getCause() != null){
            detailMessage = cause.getCause().getMessage();
        }

        return generateException(exceptionClass, errorCode, (!Objects.equals(text, defaultMessage) ? errorLocale.getLanguage() : "en"), text, detailMessage);
    }

    /**
     * Set new language to use in error messages
     *
     * @param language New error language as ISO 639 alpha-2 or alpha-3 language code,
     * or a language subtag up to 8 characters in length.
     * @return true if new language was set successfully, otherwise false.
     */
    public static synchronized boolean setErrorLanguage(String language){
        errorLocale = new Locale(language);
        return true;
    }

    /**
     * Get string representation of the error code.
     *
     * @return Error code represented as a string.
     */
    @Override
    public String toString() {
        return errorCode + ": " + defaultMessage;
    }

    /**
     * Get default message of an error code.
     * @return Default message.
     */
    String getDefaultMessage() {
        return defaultMessage;
    }

    /**
     * Get numerical error code value as a string.
     *
     * @return Numerical error code value.
     */
    String getErrorCode() {
        return errorCode;
    }

    /**
     * Get message code to use for internationalization.
     *
     * @return Message code of error message.
     */
    String getMessageCode() {
        return messageCode;
    }

    /**
     * Get message using message source.
     *
     * @param messageSource Message source to use when resolving the error message by its message code.
     * @return Message resolved through given message source or default message if message source is null.
     */
    String getMessage(MessageSource messageSource){
        return messageSource != null ? messageSource.getMessage(messageCode, null, defaultMessage, errorLocale) : defaultMessage;
    }

    private static BaseAPIException generateException(Class<?> exceptionClass, String errorCode, String language, String message, String detailMessage){
        BaseAPIException exception;
        Message errorMessage = new Message();

        try {
            Constructor<?> ctor = exceptionClass.getConstructor(String.class, Message.class, String.class);
            errorMessage.setLang(language);
            errorMessage.setText(message);
            exception = (BaseAPIException)ctor.newInstance(new Object[] { errorCode, errorMessage, detailMessage});
        } catch(Exception e){
            errorMessage.setLang("en");
            errorMessage.setText("Failed to create exception");
            exception = new ServerErrorException(INTERNAL_ERROR.errorCode, errorMessage, e.getMessage());
        }
        return exception;
    }
}