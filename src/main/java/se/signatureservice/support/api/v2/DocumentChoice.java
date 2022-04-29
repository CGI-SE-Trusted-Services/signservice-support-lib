package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.*;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="DocumentResponseChoiceType")
@XmlAccessorType(XmlAccessType.FIELD)
public class DocumentChoice {


    @XmlElements({
            @XmlElement(name = "document", type = Document.class, required = true),
            @XmlElement(name = "documentRef", type = DocumentRef.class, required = true)
    })
    Object document;

    public Object getDocument() {
        return document;
    }

    public void setDocument(Object document) {
        this.document = document;
    }
}
