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
import java.util.ArrayList;
import java.util.List;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="VerifyTransactionResponseType", propOrder = {"transactionId","verifiedDocuments"})
@XmlAccessorType(XmlAccessType.FIELD)
public class VerifyTransactionResponse extends AbstractVerifiedType{

    @XmlElement(name="transactionId")
    private String transactionId;

    @XmlElement(name="verifiedDocuments", required = true)
    private VerifiedDocuments verifiedDocuments;

    public VerifiedDocuments getVerifiedDocuments() {
        return verifiedDocuments;
    }

    public void setVerifiedDocuments(VerifiedDocuments verifiedDocuments) {
        this.verifiedDocuments = verifiedDocuments;
    }

    /**
     * Created by philip on 2017-04-13.
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "VerifiedDocumentsType", propOrder = {
            "verifiedDocuments"
    })
    public static class VerifiedDocuments {

        public VerifiedDocuments(){}

        public VerifiedDocuments(List<VerifyDocumentResponse> verifiedDocuments){
            this.verifiedDocuments = verifiedDocuments;
        }

        @XmlElement(required = true)
        protected List<VerifyDocumentResponse> verifiedDocuments;

        public List<VerifyDocumentResponse> getVerifyDocumentResponse() {
            if (verifiedDocuments == null) {
                verifiedDocuments = new ArrayList<VerifyDocumentResponse>();
            }
            return this.verifiedDocuments;
        }
    }
}
