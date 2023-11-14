package se.signatureservice.support.api.v2;

import se.signatureservice.support.utils.SerializableUtils;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="DocumentRefType", propOrder = {"referenceId"})
@XmlAccessorType(XmlAccessType.FIELD)
public class DocumentRef implements Externalizable {
    private static final long serialVersionUID = 1L;

    private static final int LATEST_VERSION = 1;

    @XmlElement(required = true)
    private String referenceId = null;

    public String getReferenceId() {
        return referenceId;
    }

    public void setReferenceId(String referenceId) {
        this.referenceId = referenceId;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(LATEST_VERSION);
        SerializableUtils.serializeNullableString(out, referenceId);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        int ver = in.readInt();
        referenceId = SerializableUtils.deserializeNullableString(in);
    }
}
