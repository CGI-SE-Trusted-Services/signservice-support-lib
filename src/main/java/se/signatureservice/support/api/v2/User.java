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
import java.io.Externalizable;
import java.io.Serializable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="UserType", propOrder = {"userId","role","userAttributes"})
@XmlAccessorType(XmlAccessType.FIELD)
public class User implements Externalizable {
    private static final long serialVersionUID = 1L;

    private static final int LATEST_VERSION = 1;

    @XmlElement(required = true)
    private String userId;

    @XmlElement()
    private String role;

    @XmlElement()
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

        List<Serializable> deserializedList = SerializableUtils.deserializeNullableList(in);
        userAttributes = (deserializedList != null && !deserializedList.isEmpty()) ? (List)deserializedList.get(0) : null;
    }

    /**
     * Builder class to use when building a User instance.
     */
    public static class Builder {
        private String userId;
        private String role;
        private List<Attribute> attributes;

        /**
         * Create new TransactionSigner builder
         */
        public Builder(){
        }

        /**
         * Specify user ID.
         *
         * @param userId User ID.
         * @return Updated builder.
         */
        public Builder userId(String userId){
            this.userId = userId;
            return this;
        }

        /**
         * Specify user role.
         *
         * @param role User role.
         * @return Updated builder.
         */
        public Builder role(String role){
            this.role = role;
            return this;
        }

        /**
         * Specify user attributes.
         *
         * @param attributes User attributes to use.
         * @return Updated builder.
         */
        public Builder attributes(List<Attribute> attributes){
            this.attributes = attributes;
            return this;
        }

        /**
         * Add user attribute.
         *
         * @param key Attribute key.
         * @param value Attribute value.
         * @return Updated builder.
         */
        public Builder addAttribute(String key, String value){
            if(attributes == null){
                attributes = new ArrayList<>();
            }
            Attribute attr = new Attribute();
            attr.setKey(key);
            attr.setValue(value);
            attributes.add(attr);
            return this;
        }

        /**
         * Build the User.
         *
         * @return User instance based on builder settings.
         */
        public User build() {
            User user = new User();
            user.setUserId(userId);
            user.setRole(role);
            user.setUserAttributes(attributes);
            return user;
        }
    }
}
