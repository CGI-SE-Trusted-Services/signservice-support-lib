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
package se.signatureservice.support.utils;

import java.io.IOException;
import java.net.ServerSocket;

/**
 * Class containing connection help methods for testing.
 *
 * @author Cristoffer 2019-06-11
 */
public class ConnectionUtils {
    /**
     * Method that creates a ServerSocket with an automatically selected free port
     *
     * @return port number
     */
    public static int getUnusedPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Failed to find an available port", e);
        }
    }
}
