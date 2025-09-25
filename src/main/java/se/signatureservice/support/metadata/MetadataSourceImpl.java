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
 * For loading metadata from disk, and caching the results.
 * <p>
 * This implementation uses a {@link SAMLMetaDataMessageParser} to parse SAML metadata files
 * (either single {@link EntityDescriptorType} or aggregated {@link EntitiesDescriptorType})
 * into reduced metadata representations. The reduced metadata is stored in a cache keyed
 * by entity ID.
 * <p>
 * Thread safety:
 * - The internal cache is a {@link ConcurrentHashMap}, so reads/writes are safe.
 * - The {@link #fromBytes(byte[], boolean)} method is synchronized since the parser
 * is not guaranteed to be thread-safe.
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
     * Read a SAML metadata file, parse all contained entity descriptors,
     * convert them to {@link ReducedMetadata}, and cache them by entity ID.
     * <p>
     * The metadata signature will <strong>not</strong> be verified.
     *
     * @param file the metadata file to read
     * @throws MessageContentException    if the metadata cannot be parsed
     * @throws IOException                if the file cannot be read
     * @throws MessageProcessingException if an error occurs while parsing
     */
    public void loadMetadata(File file) throws MessageContentException, IOException, MessageProcessingException {
        loadMetadata(Files.readAllBytes(file.toPath()), false);
    }

    /**
     * Read a SAML metadata file, parse all contained entity descriptors,
     * convert them to {@link ReducedMetadata}, and cache them by entity ID.
     *
     * @param file            the metadata file to read
     * @param verifySignature whether to verify the XML signature in the metadata
     * @throws MessageContentException    if the metadata cannot be parsed
     * @throws IOException                if the file cannot be read
     * @throws MessageProcessingException if an error occurs while parsing
     */
    public void loadMetadata(File file, boolean verifySignature) throws MessageContentException, IOException, MessageProcessingException {
        loadMetadata(Files.readAllBytes(file.toPath()), verifySignature);
    }

    /**
     * Read raw SAML metadata bytes, parse all contained entity descriptors,
     * convert them to {@link ReducedMetadata}, and cache them by entity ID.
     * <p>
     * The metadata signature will <strong>not</strong> be verified.
     *
     * @param bytes the raw metadata content
     * @throws MessageContentException    if the metadata cannot be parsed
     * @throws MessageProcessingException if an error occurs while parsing
     */
    public void loadMetadata(byte[] bytes) throws MessageContentException, MessageProcessingException {
        List<ReducedMetadata> reducedMetadata = fromBytes(bytes, false);
        reducedMetadata.forEach(md -> metadata.put(md.getEntityID(), md));
    }

    /**
     * Read raw SAML metadata bytes, parse all contained entity descriptors,
     * convert them to {@link ReducedMetadata}, and cache them by entity ID.
     *
     * @param bytes           the raw metadata content
     * @param verifySignature whether to verify the XML signature in the metadata
     * @throws MessageContentException    if the metadata cannot be parsed
     * @throws MessageProcessingException if an error occurs while parsing
     */
    public void loadMetadata(byte[] bytes, boolean verifySignature) throws MessageContentException, MessageProcessingException {
        List<ReducedMetadata> reducedMetadata = fromBytes(bytes, verifySignature);
        reducedMetadata.forEach(md -> metadata.put(md.getEntityID(), md));
    }

    /**
     * Parse raw metadata bytes into a list of {@link ReducedMetadata} objects.
     * <p>
     * This method handles both single {@link EntityDescriptorType} objects
     * and nested {@link EntitiesDescriptorType} structures recursively.
     * <p>
     * Synchronized because {@link SAMLMetaDataMessageParser} is not guaranteed to be thread-safe.
     *
     * @param bytes           the raw metadata content
     * @param verifySignature whether to verify the XML signature in the metadata
     * @return a list of parsed and reduced metadata entries
     * @throws MessageContentException    if the metadata cannot be parsed
     * @throws MessageProcessingException if an error occurs while parsing
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

    /**
     * Recursively collect {@link ReducedMetadata} objects from metadata structures.
     * <p>
     * Supports both single {@link EntityDescriptorType} and aggregated
     * {@link EntitiesDescriptorType}.
     *
     * @param metaData the metadata object to collect from
     * @param list     the target list of reduced metadata entries
     */
    private static void collectMetadata(Object metaData, List<ReducedMetadata> list) {
        if (metaData instanceof EntityDescriptorType) {
            list.add(new ReducedMetadataImpl(((EntityDescriptorType) metaData)));
        } else if (metaData instanceof EntitiesDescriptorType) {
            for (Object edt : ((EntitiesDescriptorType) metaData).getEntityDescriptorOrEntitiesDescriptor()) {
                collectMetadata(edt, list);
            }
        }
    }
}