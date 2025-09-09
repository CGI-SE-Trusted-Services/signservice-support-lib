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
