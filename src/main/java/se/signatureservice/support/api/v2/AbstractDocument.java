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
package se.signatureservice.support.api.v2;

import se.signatureservice.support.utils.SerializableUtils;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;

import java.io.*;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="AbstractDocumentType")
@XmlAccessorType(XmlAccessType.FIELD)
public class AbstractDocument implements Externalizable {
    private static final long serialVersionUID = 1L;

    private static final int LATEST_VERSION = 1;

    @XmlElement(required = true)
    protected String type;

    @XmlElement(required = true)
    protected byte[] data;

    @XmlElement(required = true)
    protected String name;

    @XmlElement()
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
