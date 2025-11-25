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
package se.signatureservice.support.metadata;

import se.signatureservice.messages.metadata.ReducedMetadata;

/**
 * Allows a client to get metadata in the form of ReducedMetadata, for entityIds
 *
 * @author Fredrik
 */
public interface MetadataSource {
    ReducedMetadata getMetaData(String entityId);
}
