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
@XmlType(name="AbstractDocumentType")
@XmlAccessorType(XmlAccessType.FIELD)
public class AbstractDocument implements Externalizable {
    static final long serialVersionUID = 1L;

    private static final int LATEST_VERSION = 1;

    @XmlElement(required = true)
    protected String type;

    @XmlElement(required = true)
    protected byte[] data;

    @XmlElement(required = true)
    protected String name;

    @XmlElement(required = false)
    protected String referenceId = null;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getReferenceId() {
        return referenceId;
    }

    public void setReferenceId(String referenceId) {
        this.referenceId = referenceId;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(LATEST_VERSION);
        SerializableUtils.serializeNullableString(out, type);
        SerializableUtils.serializeNullableByteArray(out, data);
        SerializableUtils.serializeNullableString(out, name);
        SerializableUtils.serializeNullableString(out, referenceId);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        int ver = in.readInt();
        type = SerializableUtils.deserializeNullableString(in);
        data = SerializableUtils.deserializeNullableByteArray(in);
        name = SerializableUtils.deserializeNullableString(in);
        referenceId = SerializableUtils.deserializeNullableString(in);
    }
}
