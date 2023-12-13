/************************************************************************
 *                                                                       *
 *  Signservice Support Lib                                              *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  (LGPL-3.0-or-later)                                                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.common.cache;

import org.certificateservices.messages.utils.DefaultSystemTime;
import org.certificateservices.messages.utils.SystemTime;
import se.signatureservice.configuration.common.InternalErrorException;
import se.signatureservice.configuration.common.InvalidArgumentException;
import se.signatureservice.configuration.common.cache.CacheProvider;
import se.signatureservice.configuration.common.cache.MetaData;

import java.io.IOException;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of cache provider that stores everything in memory as an in-memory map.
 * <p>
 * The implementation only supports time to live.
 *
 * Created by philip on 08/02/17.
 */
public class SimpleCacheProvider implements CacheProvider {

    SystemTime systemTime = new DefaultSystemTime();

    private final ConcurrentHashMap<String,Object> objects;
    private final ConcurrentHashMap<String, Date> expireDates;

    public SimpleCacheProvider(){
        objects = new ConcurrentHashMap<String,Object>();
        expireDates = new ConcurrentHashMap<String,Date>();
    }

    @Override
    public void init(Properties properties) throws InvalidArgumentException, IOException, InternalErrorException {

    }

    @Override
    public String get(String key) throws InvalidArgumentException, IOException, InternalErrorException {
        Object o = getObject(key);
        if(o == null || o instanceof String){
            return (String)o;
        }
        throw new InvalidArgumentException("Error supplied key didn't match a String value object");
    }

    @Override
    public String get(String contextId, String key) throws InvalidArgumentException, IOException, InternalErrorException {
        return get(contextId + ";" + key);
    }

    @Override
    public byte[] getBinary(String key) throws InvalidArgumentException, IOException, InternalErrorException {
        Object o = getObject(key);
        if(o == null || o instanceof byte[]){
            return (byte[]) o;
        }
        throw new InvalidArgumentException("Error supplied key didn't match a byte[] value object");
    }

    @Override
    public byte[] getBinary(String contextId, String key) throws InvalidArgumentException, IOException, InternalErrorException {
        return getBinary(contextId + ";" + key);
    }

    @Override
    public void set(String key, String value) throws InvalidArgumentException, IOException, InternalErrorException {
        setObject(key,value,null);
    }

    @Override
    public void set(String contextId, String key, String value) throws InvalidArgumentException, IOException, InternalErrorException {
        set(contextId + ";" + key, value);
    }

    @Override
    public void set(String key, String value, MetaData metaData) throws InvalidArgumentException, IOException, InternalErrorException {
        setObject(key,value,metaData);
    }

    @Override
    public void set(String contextId, String key, String value, MetaData metaData) throws InvalidArgumentException, IOException, InternalErrorException {
        set(contextId + ";" + key, value, metaData);
    }

    @Override
    public void set(String key, byte[] value) throws InvalidArgumentException, IOException, InternalErrorException {
        setObject(key,value,null);
    }

    @Override
    public void set(String contextId, String key, byte[] value) throws InvalidArgumentException, IOException, InternalErrorException {
        setObject(contextId + ";" + key, value,null);
    }

    @Override
    public void set(String key, byte[] value, MetaData metaData) throws InvalidArgumentException, IOException, InternalErrorException {
        setObject(key,value,metaData);
    }

    @Override
    public void set(String contextId, String key, byte[] value, MetaData metaData) throws InvalidArgumentException, IOException, InternalErrorException {
        set(contextId + ";" + key, value, metaData);
    }

    @Override
    public void delete(String key) throws InvalidArgumentException, IOException, InternalErrorException {
        deleteObject(key);
    }

    @Override
    public void delete(String contextId, String key) throws InvalidArgumentException, IOException, InternalErrorException {
        deleteObject(contextId + ";" + key);
    }

    @Override
    public void close() throws IOException, InternalErrorException {

    }

    private Object getObject(String key){
        Object o = objects.get(key);
        if(o != null){
            if(expireDates.containsKey(key)){
                Date expireDate  = expireDates.get(key);
                if(systemTime.getSystemTime().after(expireDate)){
                    objects.remove(key);
                    expireDates.remove(key);
                    o = null;
                }
            }
        }
        return o;
    }

    private void setObject(String key, Object value, MetaData metaData){
        if(value != null){
            objects.put(key,value);
        } else objects.remove(key);

        if(metaData != null && metaData.getTimeToLive() != null){
            expireDates.put(key, new Date(systemTime.getSystemTimeMS() + (metaData.getTimeToLive() * 1000)));
        } else expireDates.remove(key);
    }

    private void deleteObject(String key) {
        objects.remove(key);
        expireDates.remove(key);
    }
}
