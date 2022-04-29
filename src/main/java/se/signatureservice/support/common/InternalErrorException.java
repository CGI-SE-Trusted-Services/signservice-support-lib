package se.signatureservice.support.common;

/**
 * Exception that indicates an internal error occurred in the system.
 *
 * Created by philip on 08/02/17.
 */
public class InternalErrorException extends Exception {

    /**
     * Exception that indicates an internal error occurred in the system.
     * @param message description of the exception.
     */
    public InternalErrorException(String message){
        super(message);
    }

    /**
     * Exception that indicates an internal error occurred in the system.
     * @param message description of the exception.
     * @param cause optional cause of the exception.
     */
    public InternalErrorException(String message, Throwable cause){
        super(message,cause);
    }
}
