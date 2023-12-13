package se.signatureservice.support.api.v2;

import org.apache.commons.io.IOUtils;
import se.signatureservice.support.utils.SerializableUtils;
import se.signatureservice.support.utils.SupportLibraryUtils;

import javax.xml.bind.annotation.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by philip on 2017-04-13.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DocumentRequestsType", propOrder = {
        "documents"
})
public class DocumentRequests implements Externalizable {
    private static final long serialVersionUID = 1L;

    private static final int LATEST_VERSION = 1;

    public DocumentRequests(){}

    public DocumentRequests(List<Object> documents){
        this.documents = documents;
    }

    @XmlElements({
            @XmlElement(name = "document", type = DocumentSigningRequest.class, required = true),
            @XmlElement(name = "documentRef", type = DocumentRef.class, required = true)
    })
    protected List<Object> documents;

    public List<Object> getDocuments() {
        if (documents == null) {
            documents = new ArrayList<Object>();
        }
        return this.documents;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(LATEST_VERSION);
        SerializableUtils.serializeNullableList(out, documents);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        int ver = in.readInt();
        documents = (List) SerializableUtils.deserializeNullableList(in);
    }

    /**
     * Builder class to help when building a DocumentRequests instance.
     */
    public static class Builder {
        private final DocumentRequests documentRequests;

        /**
         * Create new TransactionSigner builder
         */
        public Builder(){
            documentRequests = new DocumentRequests();
            documentRequests.documents = new ArrayList<>();
        }

        public Builder addCMSDocument(String fileName, FileInputStream fileStream) throws IOException {
            return addDocument(fileName, "application/octet-stream", fileStream, SupportLibraryUtils.generateReferenceId());
        }

        public Builder addCMSDocument(String filePath) throws IOException {
            File file = new File(filePath);
            return addDocument(file.getName(), "application/octet-stream", new FileInputStream(file), SupportLibraryUtils.generateReferenceId());
        }

        public Builder addPDFDocument(String fileName, FileInputStream fileStream) throws IOException {
            return addDocument(fileName, "application/pdf", fileStream, SupportLibraryUtils.generateReferenceId());
        }

        public Builder addPDFDocument(String filePath) throws IOException {
            File file = new File(filePath);
            return addDocument(file.getName(), "application/pdf", new FileInputStream(file), SupportLibraryUtils.generateReferenceId());
        }

        public Builder addXMLDocument(String fileName, FileInputStream fileStream) throws IOException {
            return addDocument(fileName, "text/xml", fileStream, SupportLibraryUtils.generateReferenceId());
        }

        public Builder addXMLDocument(String filePath) throws IOException {
            File file = new File(filePath);
            return addDocument(file.getName(), "text/xml", new FileInputStream(file), SupportLibraryUtils.generateReferenceId());
        }

        public Builder addDocument(String fileName, String fileType, InputStream fileData, String referenceId) throws IOException {
            DocumentSigningRequest document = new DocumentSigningRequest();
            document.setReferenceId(referenceId);
            document.setName(fileName);
            document.setType(fileType);
            document.setData(IOUtils.toByteArray(fileData));
            documentRequests.documents.add(document);
            return this;
        }

        /**
         * Build the DocumentRequests instance.
         *
         * @return DocumentRequests instance based on builder settings.
         */
        public DocumentRequests build() {
            return documentRequests;
        }
    }
}
