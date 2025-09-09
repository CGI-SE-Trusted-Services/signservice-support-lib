package se.signatureservice.support.metadata;

import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.metadata.ReducedMetadata;
import se.signatureservice.messages.metadata.ReducedMetadataIO;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * For loading metadata from disk, and cache the results
 *
 * @author Fredrik
 */
public class MetadataSourceImpl implements MetadataSource {
    private final Map<String, ReducedMetadata> metadata = new ConcurrentHashMap<>();

    @Override
    public ReducedMetadata getMetaData(String entityId) {
        return metadata.get(entityId);
    }

    public Map<String, ReducedMetadata> getMetadata() {
        return metadata;
    }

    public void loadMetadata(File file) throws MessageContentException, IOException, MessageProcessingException {
        List<ReducedMetadata> reducedMetadata = ReducedMetadataIO.fromFile(file, false);
        reducedMetadata.forEach(md -> metadata.put(md.getEntityID(), md));
    }

    public void loadMetadata(byte[] bytes) throws MessageContentException, MessageProcessingException {
        List<ReducedMetadata> reducedMetadata = ReducedMetadataIO.fromBytes(bytes, false);
        reducedMetadata.forEach(md -> metadata.put(md.getEntityID(), md));
    }

    public void loadMetadataInDirectory(File directory) throws MessageContentException, MessageProcessingException, IOException {
        try(Stream<Path> list = Files.find(directory.toPath(), 1, (p, attr) -> { return p.toString().endsWith(".xml");})) {
            for (Path path : list.collect(Collectors.toList())) {
                loadMetadata(path.toFile());
            }
        }
    }
}
