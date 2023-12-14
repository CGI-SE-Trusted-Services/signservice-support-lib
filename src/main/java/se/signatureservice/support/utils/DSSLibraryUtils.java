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

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.signatureservice.support.api.v2.AbstractDocument;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

/**
 * Utility methods when working with DSS library.
 */
public class DSSLibraryUtils {

    private static final Logger log = LoggerFactory.getLogger(DSSLibraryUtils.class);

    /**
     * Create DSSDocument from a given AbstractDocument
     * @param document AbstractDocument to create DSSDocument from
     * @return DSSDocument based on given AbstractDocument
     */
    public static DSSDocument createDSSDocument(AbstractDocument document) {
        InMemoryDocument dssDocument = new InMemoryDocument();
        dssDocument.setName(document.getName());
        dssDocument.setBytes(document.getData());
        dssDocument.setMimeType(MimeType.fromMimeTypeString(document.getType()));
        return dssDocument;
    }

    /**
     * Create a DSSDocument by loading data using a given path. The path
     * can be classpath or filesystem, where classpath takes precedence.
     * Mimetype is assumed to be binary.
     *
     * @param path Path to file on classpath or filesystem.
     * @return DSSDocument based on given parameters.
     */
    public static DSSDocument createDSSDocument(String path){
        return createDSSDocument(path, MimeTypeEnum.BINARY);
    }

    /**
     * Create a DSSDocument by loading data using a given path. The path
     * can be classpath or filesystem, where classpath takes precedence.
     *
     * @param path Path to file on classpath or filesystem.
     * @param mimeType Mimetype of file.
     * @return DSSDocument based on given parameters.
     */
    public static DSSDocument createDSSDocument(String path, MimeType mimeType){
        InMemoryDocument dssDocument = null;

        if(path != null){
            byte[] bytes = null;
            File file = new File(path);
            InputStream fileStream = DSSLibraryUtils.class.getResourceAsStream(path);
            if(fileStream == null){
                if(file.exists() && file.canRead()){
                    try {
                        bytes = Files.readAllBytes(file.toPath());
                    } catch(IOException e){
                        log.error("Failed to read file: " + path);
                    }
                }
            } else {
                try {
                    bytes = IOUtils.toByteArray(fileStream);
                } catch(IOException e){
                    log.error("Failed to read file stream: " + path);
                }
            }

            if(bytes != null){
                dssDocument = new InMemoryDocument();
                dssDocument.setName(file.getName());
                dssDocument.setBytes(bytes);
                dssDocument.setMimeType(mimeType);
            }
        }

        return dssDocument;
    }
}
