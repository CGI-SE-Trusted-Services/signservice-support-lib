package se.signatureservice.support.common.cache;

import java.util.Properties;

/**
 * Meta data class containing extra related information about a cached entry.
 *
 * Created by philip on 08/02/17.
 */
public class MetaData {

    Integer timeToLive;
    Properties properties;

    /**
     * Empty constructor with no timeToLive nor properties
     */
    public MetaData(){
    }

    /**
     * Constructor for timeToLive and given properties
     * @param timeToLive time to live of the object in seconds.
     * @param properties releated properties of a cached object, valid values is up to underlying implementation.
     */
    public MetaData(Integer timeToLive, Properties properties){
        this.timeToLive = timeToLive;
        this.properties = properties;
    }

    /**
     * Constructor for timeToLive restricted objects.
     * @param timeToLive time to live of the object in seconds.
     */
    public MetaData(Integer timeToLive){
        this(timeToLive,null);
    }

    /**
     *
     * @return time to live of related objects in seconds.
     */
    public Integer getTimeToLive(){
        return timeToLive;
    }

    /**
     *
     * @param timeToLive time to live of the object in seconds.
     */
    public void setTimeToLive(Integer timeToLive){
        this.timeToLive = timeToLive;
    }

    /**
     *
     * @param key key or related property
     * @return the related value of null if no related property found.
     */
    String getProperty(String key){
        if(properties == null){
            return null;
        }

        return properties.getProperty(key);
    }

    /**
     *
     * @param key the key of the related property
     * @param value the value of the related property
     */
    void setProperty(String key, String value){
        if(properties == null){
            properties = new Properties();
        }
        properties.setProperty(key,value);
    }

    public String toString(){
        return "MetaData [ timeToLive=" + timeToLive + ", properties=" + (properties != null ? properties.toString() : null) + " ]";
    }

}
