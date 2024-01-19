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
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Created by philip on 2017-04-12.
 */
@XmlType(name="DocumentResponseType", propOrder = {"signatures","hasDetachedSignature","detachedSignatureData","validationInfo"})
@XmlAccessorType(XmlAccessType.FIELD)
public class Document extends AbstractDocument {


    @XmlElement(name="signatures")
    private Signatures signatures;

    @XmlElement(name="hasDetachedSignature",defaultValue = "false")
    private boolean hasDetachedSignature;

    @XmlElement(name="detachedSignatureData")
    protected byte[] detachedSignatureData;

    @XmlElement(name="validationInfo")
    private VerifyDocumentResponse validationInfo;

    public Signatures getSignatures() {
        return signatures;
    }

    public void setSignatures(Signatures signatures) {
        this.signatures = signatures;
    }

    public boolean isHasDetachedSignature() {
        return hasDetachedSignature;
    }

    public void setHasDetachedSignature(boolean hasDetachedSignature) {
        this.hasDetachedSignature = hasDetachedSignature;
    }

    public byte[] getDetachedSignatureData() {
        return detachedSignatureData;
    }

    public void setDetachedSignatureData(byte[] detachedSignatureData) {
        this.detachedSignatureData = detachedSignatureData;
    }

    public VerifyDocumentResponse getValidationInfo(){
        return validationInfo;
    }

    public void setValidationInfo(VerifyDocumentResponse validationInfo){
        this.validationInfo = validationInfo;
    }
}
