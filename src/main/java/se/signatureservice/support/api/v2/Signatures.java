package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by philip on 2017-04-13.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SignersType", propOrder = {
        "signatures"
})
public class Signatures {

    public Signatures(){}

    public Signatures(List<Signature> signatures){
        this.signatures = signatures;
    }

    @XmlElement(required = true)
    protected List<Signature> signatures;

    public List<Signature> getSigner() {
        if (signatures == null) {
            signatures = new ArrayList<Signature>();
        }
        return this.signatures;
    }
}
