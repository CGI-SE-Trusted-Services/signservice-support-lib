package se.signatureservice.support.common;

/**
 * Exception that indicates an supplied argument to a method was invalid.
 *
 * Created by philip on 08/02/17.
 */
public class InvalidArgumentException extends Exception {

    /**
     * Exception that indicates an supplied argument to a method was invalid.
     * @param message description of the exception.
     */
    public InvalidArgumentException(String message){
        super(message);
    }

    /**
     * Exception that indicates an supplied argument to a method was invalid.
     * @param message description of the exception.
     * @param cause optional cause of the exception.
     */
    public InvalidArgumentException(String message, Throwable cause){
        super(message,cause);
    }
}
