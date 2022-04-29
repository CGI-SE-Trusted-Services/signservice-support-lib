package se.signatureservice.support.utils;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import se.signatureservice.support.api.v2.AbstractDocument;

/**
 * Utility methods when working with DSS library.
 */
public class DSSLibraryUtils {

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
}
