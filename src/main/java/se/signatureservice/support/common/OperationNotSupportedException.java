package se.signatureservice.support.common;

/**
 * Exception that indicates called method isn't supported by implementation.
 *
 * Created by philip on 08/02/17.
 */
public class OperationNotSupportedException extends Exception {

    /**
     * Exception that indicates called method isn't supported by implementation.
     * @param message description of the exception.
     */
    public OperationNotSupportedException(String message){
        super(message);
    }

}
