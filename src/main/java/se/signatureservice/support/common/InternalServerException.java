/************************************************************************
*                                                                       *
*  Certificate Service - Common          ,                               *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package se.signatureservice.support.common;

/**
 * Exception thrown by external API interfaces indicating something went wrong internally 
 * within the application due to configuration error or problems with underlying systems.
 * 
 * @author Philip Vendil May 11, 2012
 *
 */
public class InternalServerException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Exception thrown by external API interfaces indicating something went wrong internally 
	 * within the application due to configuration error or problems with underlying systems.
	 * 
	 * @param message describing message about the exception.
	 */
	public InternalServerException(String message) {
		super(message);

	}
	
	/**
	* Exception thrown by external API interfaces indicating something went wrong internally
	* within the application due to configuration error or problems with underlying systems.
	*
	* @param message describing message about the exception.
	* @param cause the cause of the exception
	*/
   public InternalServerException(String message, Throwable cause) {
	   super(message, cause);

   }

}
