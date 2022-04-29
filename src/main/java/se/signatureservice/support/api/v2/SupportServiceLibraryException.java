/************************************************************************
 *                                                                       *
 *  Signature Service - Support Service Library                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.api.v2;

/**
 * Indicates an error when using the support service library.
 *
 * @author Tobias Agerberg
 */
public class SupportServiceLibraryException extends Exception {

    /**
     * Create library exception without any specific message.
     */
    public SupportServiceLibraryException() {
        super();
    }

    /**
     * Create library exception with specific message.
     *
     * @param message Message that describes the error that caused the exception.
     */
    public SupportServiceLibraryException(String message) {
        super(message);
    }

    /**
     * Create library exception with specific message and an additional inner exception.
     *
     * @param message Message that describes the error that caused the exception.
     * @param cause Additional related exception causing the error.
     */
    public SupportServiceLibraryException(String message, Throwable cause) {
        super(message, cause);
    }
}
