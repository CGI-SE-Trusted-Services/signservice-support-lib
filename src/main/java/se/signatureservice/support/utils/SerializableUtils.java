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
package se.signatureservice.support.utils;

import se.signatureservice.configuration.support.system.Constants;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;
import java.util.*;

/**
 * Contains help methods used when manually serializing objects.
 *
 * @author Philip Vendil
 */
public class SerializableUtils {

    /**
     * Help method to serialize a string that might be null.
     *
     * @throws IOException I/O exceptions during string serialization.
     */
    public static void serializeNullableString(ObjectOutput out, String string) throws IOException {
        out.writeBoolean(string != null);
        if (string != null) {
            out.writeUTF(string);
        }
    }

    /**
     * Help method to deserialize a String that might be null.
     *
     * @throws IOException I/O exceptions during string deserialization.
     */
    public static String deserializeNullableString(ObjectInput input) throws IOException {
        return input.readBoolean() ? input.readUTF() : null;
    }

    /**
     * Help method to serialize a byte array that might be null.
     *
     * @throws IOException I/O exceptions during byte array serialization.
     */
    public static void serializeNullableByteArray(ObjectOutput out, byte[] data) throws IOException {
        out.writeInt(data != null ? data.length : -1);
        if (data != null) {
            out.write(data);
        }
    }

    /**
     * Help method to deserialize a byte array that might be null.
     *
     * @throws IOException I/O exceptions during byte array deserialization.
     */
    public static byte[] deserializeNullableByteArray(ObjectInput input) throws IOException {
        byte[] retval = null;
        int size = input.readInt();
        if (size >= 0) {
            int len;
            int index = 0;
            retval = new byte[size];
            while ((len = input.read(retval, index, size)) != -1) {
                index += len;
                size -= len;
                if (size == 0) {
                    break;
                }
            }
        }

        return retval;
    }

    /**
     * Help method to serialize a list of serializable objects that might be null.
     *
     * @throws IOException I/O exceptions during list serialization.
     */
    public static void serializeNullableList(ObjectOutput out, List<Object> l) throws IOException {
        out.writeInt(l != null ? l.size() : -1);
        if (l != null) {
            for (Object obj : l) {
                out.writeObject(obj);
            }
        }
    }

    /**
     * Help method to deserialize a list of serializable objects that might be null.
     *
     * @throws IOException            I/O exceptions during list deserialization.
     * @throws ClassNotFoundException class not found.
     */
    public static List<Serializable> deserializeNullableList(ObjectInput input) throws IOException, ClassNotFoundException {
        int size = input.readInt();
        if (size >= 0) {
            List<Serializable> retval = new ArrayList<>(size);
            for (int i = 0; i < size; i++) {
                retval.add((Serializable) input.readObject());
            }
            return retval;
        }
        return null;
    }

    /**
     * Help method to serialize a object that might be null.
     */
    public static void serializeNullableObject(ObjectOutput out, Serializable object) throws IOException {
        out.writeBoolean(object != null);
        if (object != null) {
            out.writeObject(object);
        }
    }

    /**
     * Help method to deserialize a object that might be null.
     */
    public static Object deserializeNullableObject(ObjectInput input) throws IOException, ClassNotFoundException {
        return input.readBoolean() ? input.readObject() : null;
    }

    /**
     * Help method to serialize a date that might be null.
     */
    public static void serializeNullableDate(ObjectOutput out, Date date) throws IOException {
        out.writeLong(date != null ? date.getTime() : Constants.NOT_SET);
    }

    /**
     * Help method to deserialize a date that might be null.
     */
    public static Date deserializeNullableDate(ObjectInput input) throws IOException {
        long timeStamp = input.readLong();
        return timeStamp != Constants.NOT_SET ? new Date(timeStamp) : null;
    }
}
