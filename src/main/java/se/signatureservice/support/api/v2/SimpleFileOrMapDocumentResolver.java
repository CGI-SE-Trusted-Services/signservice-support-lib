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
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A basic DocumentResolver implementation that resolves documents either from local file paths
 * (relative to an optional base directory or absolute) or from a pre-loaded in-memory map.
 */
public class SimpleFileOrMapDocumentResolver implements DocumentResolver {

    private final String baseDirectory;
    private final Map<String, byte[]> documentContentMap;
    private final Map<String, String> documentMimeTypeMap;
    private final Map<String, String> documentNameMap;

    /**
     * Default constructor. Documents can only be resolved if they are pre-loaded
     * or if the referenceId is an absolute path.
     */
    public SimpleFileOrMapDocumentResolver() {
        this(null);
    }

    /**
     * Constructor that takes a base directory. If a referenceId is not found
     * in the pre-loaded map, it will be treated as a path relative to this baseDirectory.
     *
     * @param baseDirectoryPath The base directory to resolve relative file paths. Can be null.
     */
    public SimpleFileOrMapDocumentResolver(String baseDirectoryPath) {
        this.baseDirectory = baseDirectoryPath;
        this.documentContentMap = new HashMap<>();
        this.documentMimeTypeMap = new HashMap<>();
        this.documentNameMap = new HashMap<>();
    }

    /**
     * Pre-loads a document into the in-memory map for resolution.
     *
     * @param referenceId The ID to associate with this document.
     * @param content     The byte content of the document.
     * @param mimeType    The MIME type of the document (e.g., "application/pdf").
     * @param name        The name of the document (e.g., "mydoc.pdf").
     */
    public void addDocument(String referenceId, byte[] content, String mimeType, String name) {
        if (referenceId == null || content == null || mimeType == null || name == null) {
            throw new IllegalArgumentException("All parameters must be non-null to add a document.");
        }
        documentContentMap.put(referenceId, content);
        documentMimeTypeMap.put(referenceId, mimeType);
        documentNameMap.put(referenceId, name);
    }

    @Override
    public byte[] resolveDocumentData(String referenceId) throws IOException, DocumentNotFoundException {
        if (documentContentMap.containsKey(referenceId)) {
            return documentContentMap.get(referenceId);
        }

        Path filePath = getPath(referenceId);
        if (Files.exists(filePath) && Files.isReadable(filePath) && !Files.isDirectory(filePath)) {
            return Files.readAllBytes(filePath);
        }
        throw new DocumentNotFoundException("Document not found for referenceId: " + referenceId + (filePath != null ? " (resolved to path: " + filePath.toAbsolutePath() + ")" : ""));
    }

    @Override
    public String resolveDocumentMimeType(String referenceId) throws IOException, DocumentNotFoundException {
        if (documentMimeTypeMap.containsKey(referenceId)) {
            return documentMimeTypeMap.get(referenceId);
        }

        Path filePath = getPath(referenceId);
        String fileName = filePath.getFileName().toString().toLowerCase(Locale.ROOT);

        if (fileName.endsWith(".pdf")) {
            return "application/pdf";
        } else if (fileName.endsWith(".xml")) {
            return "text/xml";
        }

        if (Files.exists(filePath) && Files.isReadable(filePath) && !Files.isDirectory(filePath)) {
            String probedMimeType = Files.probeContentType(filePath);
            if (probedMimeType != null) {
                return probedMimeType;
            }
        }
        throw new DocumentNotFoundException("Could not determine MIME type for referenceId: " + referenceId);
    }

    @Override
    public String resolveDocumentName(String referenceId) throws DocumentNotFoundException {
        if (documentNameMap.containsKey(referenceId)) {
            return documentNameMap.get(referenceId);
        }

        Path filePath = getPath(referenceId);
        return filePath.getFileName().toString();
    }

    private Path getPath(String referenceId) throws DocumentNotFoundException {
        Path filePath = null;
        try {
            if (this.baseDirectory != null && !this.baseDirectory.trim().isEmpty()) {
                filePath = Paths.get(this.baseDirectory, referenceId);
            } else {
                Path potentialAbsPath = Paths.get(referenceId);
                if (potentialAbsPath.isAbsolute()) {
                    filePath = potentialAbsPath;
                } else {
                    if (!documentContentMap.containsKey(referenceId)) {
                        throw new DocumentNotFoundException("Cannot resolve referenceId '" + referenceId + "' as a file path: No base directory set and not an absolute path.");
                    }
                }
            }
        } catch (InvalidPathException e) {
            throw new DocumentNotFoundException("Invalid path format for referenceId: " + referenceId, e);
        }
        if (filePath == null && !documentContentMap.containsKey(referenceId)) {
            throw new DocumentNotFoundException("Unable to determine file path for referenceId: " + referenceId);
        }
        return filePath;
    }
}