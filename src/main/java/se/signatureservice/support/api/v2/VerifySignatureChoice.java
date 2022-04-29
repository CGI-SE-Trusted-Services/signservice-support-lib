package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.*;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="VerifySignatureChoiceType")
@XmlAccessorType(XmlAccessType.FIELD)
public class VerifySignatureChoice {


    @XmlElements({
            @XmlElement(name = "document", type = Document.class, required = true),
            @XmlElement(name = "documentRef", type = DocumentRef.class, required = true)
    })
    Object object;

    public Object getObject() {
        return object;
    }

    public void setObject(Object object) {
        this.object = object;
    }
}
