/************************************************************************
 *                                                                       *
 *  Signature Service - Support Service Library                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.utils;

import se.signatureservice.support.system.Constants;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Contains help methods used when manually serializing objects.
 *
 * @author Philip Vendil
 */
public class SerializableUtils {

    /**
     * Help method to serialize a string that might be null.
     * @throws IOException
     */
    public static void serializeNullableString(ObjectOutput out, String string) throws IOException{
        if(string != null){
            out.writeBoolean(true);
            out.writeUTF(string);
        } else {
            out.writeBoolean(false);
        }
    }

    /**
     * Help method to deserialize a String that might be null.
     * @throws IOException
     */
    public static String deserializeNullableString(ObjectInput input) throws IOException{
        String retval = null;
        boolean exist = input.readBoolean();
        if(exist) {
            retval = input.readUTF();
        }

        return retval;
    }

    /**
     * Help method to serialize a byte array that might be null.
     * @throws IOException
     */
    public static void serializeNullableByteArray(ObjectOutput out, byte[] data) throws IOException{
        if(data != null){
            out.writeInt(data.length);
            out.write(data);
        }else{
            out.writeInt(-1);
        }
    }

    /**
     * Help method to deserialize a byte array that might be null.
     * @throws IOException
     */
    public static byte[] deserializeNullableByteArray(ObjectInput input) throws IOException{
        byte[] retval  = null;
        int size = input.readInt();
        if(size >= 0){
            int len = 0;
            int index=0;
            retval = new byte[size];
            while((len = input.read(retval, index, size)) != -1){
                index += len;
                size -= len;
                if(size == 0){
                    break;
                }
            }
        }

        return retval;
    }

    /**
     * Help method to serialize a list of serializable objects that might be null.
     * @throws IOException
     */
    public static void serializeNullableList(ObjectOutput out, List<Object> l) throws IOException{
        if(l != null){
            out.writeInt(l.size());

            for(Object s : l){
                out.writeObject(s);
            }
        }else{
            out.writeInt(-1);
        }
    }

    /**
     * Help method to deserialize a list of serializable objects that might be null.
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static List<Serializable> deserializeNullableList(ObjectInput input) throws IOException, ClassNotFoundException{
        List<Serializable> retval  = null;
        int size = input.readInt();
        if(size >= 0){
            retval = new ArrayList();
            for(int i=0;i<size;i++){
                retval.add((Serializable) input.readObject());
            }
        }

        return retval;
    }

    /**
     * Help method to serialize a object that might be null.
     */
    public static void serializeNullableObject(ObjectOutput out, Serializable object) throws IOException {
        if(object != null){
            out.writeBoolean(true);
            out.writeObject(object);
        } else {
            out.writeBoolean(false);
        }
    }

    /**
     * Help method to deserialize a object that might be null.
     */
    public static Object deserializeNullableObject(ObjectInput input) throws IOException, ClassNotFoundException {
        Object retval = null;
        boolean exist = input.readBoolean();
        if(exist){
            retval = input.readObject();
        }

        return retval;
    }

    /**
     * Help method to serialize a date that might be null.
     */
    public static void serializeNullableDate(ObjectOutput out, Date date) throws IOException {
        if(date != null){
            out.writeLong(date.getTime());
        }else{
            out.writeLong(Constants.NOT_SET);
        }
    }

    /**
     * Help method to deserialize a date that might be null.
     */
    public static Date deserializeNullableDate(ObjectInput input) throws IOException {
        Date retval = null;
        long timeStamp = input.readLong();
        if(timeStamp != Constants.NOT_SET){
            retval = new Date(timeStamp);
        }

        return retval;
    }
}
