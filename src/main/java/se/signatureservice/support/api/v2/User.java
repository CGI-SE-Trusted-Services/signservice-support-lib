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
import java.util.Collections;
import java.util.List;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="UserType", propOrder = {"userId","role","userAttributes"})
@XmlAccessorType(XmlAccessType.FIELD)
public class User implements Externalizable {
    static final long serialVersionUID = 1L;

    private static final int LATEST_VERSION = 1;

    @XmlElement(required = true)
    private String userId;

    @XmlElement(required = false)
    private String role;

    @XmlElement(required = false)
    private List<Attribute> userAttributes;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public List<Attribute> getUserAttributes() {
        return userAttributes;
    }

    public void setUserAttributes(List<Attribute> userAttributes) {
        this.userAttributes = userAttributes;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(LATEST_VERSION);
        SerializableUtils.serializeNullableString(out, userId);
        SerializableUtils.serializeNullableString(out, role);
        SerializableUtils.serializeNullableList(out, Collections.singletonList(userAttributes));
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        int ver = in.readInt();
        userId = SerializableUtils.deserializeNullableString(in);
        role = SerializableUtils.deserializeNullableString(in);
        userAttributes = (List) SerializableUtils.deserializeNullableList(in);
    }
}
