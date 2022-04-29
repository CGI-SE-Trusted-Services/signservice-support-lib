package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="CompleteSignatureResponseType", propOrder = {"documents"})
@XmlAccessorType(XmlAccessType.FIELD)
public class CompleteSignatureResponse {

    @XmlElement(required = true)
    protected DocumentResponses documents;

    public DocumentResponses getDocuments() {
        return documents;
    }

    public void setDocuments(DocumentResponses documents) {
        this.documents = documents;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "DocumentResponsesType", propOrder = {
            "documents"
    })
    public static class DocumentResponses {

        public DocumentResponses(){}

        public DocumentResponses(List<Object> documents){
            this.documents = documents;
        }

        @XmlElements({
                @XmlElement(name = "document", type = Document.class, required = true),
                @XmlElement(name = "documentRef", type = DocumentRef.class, required = true)
        })
        protected List<Object> documents;

        public List<Object> getDocuments() {
            if (documents == null) {
                documents = new ArrayList<Object>();
            }
            return this.documents;
        }
    }
}
