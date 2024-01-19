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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import java.util.List;

/**
 * Created by philip on 2017-04-13.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class IOErrorException extends BaseAPIException {

    public IOErrorException(String code, Message internationalizedMessage, String detailMessage) {
        super(code, internationalizedMessage,detailMessage);
    }

    public IOErrorException(String code, List<Message> internationalizedMessages, String detailMessage) {
        super(code, internationalizedMessages,detailMessage);
    }
}
