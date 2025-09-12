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

import se.signatureservice.messages.ContextMessageSecurityProvider;
import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.MessageSecurityProvider;
import se.signatureservice.messages.metadata.MetadataConstants;
import se.signatureservice.messages.metadata.ReducedMetadata;
import se.signatureservice.messages.metadata.ReducedMetadataImpl;
import se.signatureservice.messages.saml2.metadata.SAMLMetaDataMessageParser;
import se.signatureservice.messages.saml2.metadata.jaxb.EntitiesDescriptorType;
import se.signatureservice.messages.saml2.metadata.jaxb.EntityDescriptorType;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * For loading metadata from disk, and cache the results
 *
 * @author Fredrik
 */
public class MetadataSourceImpl implements MetadataSource {
    private final Map<String, ReducedMetadata> metadata = new ConcurrentHashMap<>();
    private final SAMLMetaDataMessageParser messageParser;

    public MetadataSourceImpl(MessageSecurityProvider messageSecurityProvider) throws MessageProcessingException {
        this.messageParser = new SAMLMetaDataMessageParser();
        messageParser.init(messageSecurityProvider, null);
    }

    @Override
    public ReducedMetadata getMetaData(String entityId) {
        return metadata.get(entityId);
    }

    public Map<String, ReducedMetadata> getMetadata() {
        return metadata;
    }

    /**
     * Read saml entityDescriptors, convert to ReducedMetadata and store by entityID
     * @param file, the file to read
     * @param verifySignature, verify signature in saml xml
     */
    public void loadMetadata(File file, boolean verifySignature) throws MessageContentException, IOException, MessageProcessingException {
        loadMetadata(Files.readAllBytes(file.toPath()), verifySignature);
    }

    /**
     * Read saml entityDescriptors, convert to ReducedMetadata and store by entityID
     * @param bytes, the bytes to read
     * @param verifySignature, verify signature in saml xml
     */
    public void loadMetadata(byte[] bytes, boolean verifySignature) throws MessageContentException, MessageProcessingException {
        List<ReducedMetadata> reducedMetadata = fromBytes(bytes, verifySignature);
        reducedMetadata.forEach(md -> metadata.put(md.getEntityID(), md));
    }

    /**
     * Synchronized since the message parser is not necessarily thread safe
     * @param bytes, the bytes to read
     * @param verifySignature, verify signature in saml xml
     */
    private synchronized List<ReducedMetadata> fromBytes(byte[] bytes, boolean verifySignature) throws MessageProcessingException, MessageContentException {
        Object o = messageParser.parseMessage(
                new ContextMessageSecurityProvider.Context(MetadataConstants.CONTEXT_USAGE_METADATA_SIGN),
                bytes, verifySignature
        );
        var list = new LinkedList<ReducedMetadata>();
        collectMetadata(o, list);
        return list;
    }

    private static void collectMetadata(Object metaData, List<ReducedMetadata> list) {
        if (metaData instanceof EntityDescriptorType) {
            list.add(new ReducedMetadataImpl(((EntityDescriptorType) metaData)));
        } else {
            if (metaData instanceof EntitiesDescriptorType) {
                for (Object edt : ((EntitiesDescriptorType) metaData).getEntityDescriptorOrEntitiesDescriptor()) {
                    collectMetadata(edt, list);
                }
            }
        }
    }
}
