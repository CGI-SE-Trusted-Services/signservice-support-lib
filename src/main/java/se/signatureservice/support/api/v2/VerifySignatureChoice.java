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

import javax.xml.bind.annotation.*;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="VerifySignatureChoiceType")
@XmlAccessorType(XmlAccessType.FIELD)
public class VerifySignatureChoice {


    @XmlElements({
            @XmlElement(name = "document", type = Document.class, required = true),
            @XmlElement(name = "documentRef", type = DocumentRef.class, required = true)
    })
    Object object;

    public Object getObject() {
        return object;
    }

    public void setObject(Object object) {
        this.object = object;
    }
}
