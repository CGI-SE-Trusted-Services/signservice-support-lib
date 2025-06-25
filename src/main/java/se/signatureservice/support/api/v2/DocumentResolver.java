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
package se.signatureservice.support.api.v2;

import java.io.IOException;

/**
 * Defines a contract for resolving document references to their actual content,
 * MIME type, and name. Implementations handle fetching documents from various sources.
 */
public interface DocumentResolver {
    /**
     * Resolves a document reference to its byte content.
     *
     * @param referenceId The ID or reference string for the document.
     * @return The byte content of the document.
     * @throws IOException               If an I/O error occurs during resolution.
     * @throws DocumentNotFoundException If the document cannot be found for the given referenceId.
     */
    byte[] resolveDocumentData(String referenceId) throws IOException, DocumentNotFoundException;

    /**
     * Resolves the MIME type for a document reference.
     *
     * @param referenceId The ID or reference string for the document.
     * @return The MIME type string (e.g., "application/pdf").
     * @throws IOException               If an I/O error occurs during resolution.
     * @throws DocumentNotFoundException If the document metadata cannot be found.
     */
    String resolveDocumentMimeType(String referenceId) throws IOException, DocumentNotFoundException;

    /**
     * Resolves the name for a document reference.
     *
     * @param referenceId The ID or reference string for the document.
     * @return The name of the document (e.g., "mydoc.pdf").
     * @throws IOException               If an I/O error occurs during resolution.
     * @throws DocumentNotFoundException If the document metadata cannot be found.
     */
    String resolveDocumentName(String referenceId) throws IOException, DocumentNotFoundException;
}
