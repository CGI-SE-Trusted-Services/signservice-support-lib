package se.signatureservice.support.metadata;

import se.signatureservice.messages.metadata.ReducedMetadata;

public interface MetadataSource {

    ReducedMetadata getMetaData(String entityId);
}
