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

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;

/**
 * Contains various utility methods to handle dates.
 *
 * Created by agerbergt on 2017-07-05.
 */
public class DateUtils {
    private static final SimpleDateFormat xmlDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");

    /**
     * Create XMLGregorianCalendar from a given java Date object
     * @param date Date to get XMLGregorianCalendar for
     * @return Given date represented as an XMLGregorianCalendar or null if error ocurred.
     */
    public static XMLGregorianCalendar createXMLGregorianCalendar(Date date) {
        if (date == null) {
            return null;
        }

        final GregorianCalendar calendar = new GregorianCalendar();
        calendar.setTime(date);
        try {
            XMLGregorianCalendar xmlGregorianCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar);
            xmlGregorianCalendar.setFractionalSecond(null);
            xmlGregorianCalendar = xmlGregorianCalendar.normalize();
            return xmlGregorianCalendar;
        } catch (DatatypeConfigurationException ignored) { }

        return null;
    }

    /**
     * Parse XML date into Date object
     * @param xmlDate XML date string to parse
     * @return Date object based on the given XML date string
     */
    public static Date parseXMLDate(String xmlDate){
        Date date;
        try {
            date = xmlDateFormat.parse(xmlDate);
        } catch(ParseException e){
            date = null;
        }
        return date;
    }
}
