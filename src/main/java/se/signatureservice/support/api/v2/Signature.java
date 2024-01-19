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
import java.util.Date;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="SignatureType", propOrder = {"signerId","signerDisplayName","signerCertificate","issuerId","signingAlgorithm","signingDate","validFrom","validTo","levelOfAssurance"})
@XmlAccessorType(XmlAccessType.FIELD)
public class Signature {
    @XmlElement(required = true)
    private String signerId;
    @XmlElement(required = true)
    private String signerDisplayName;
    @XmlElement(required = true)
    public byte[] signerCertificate;

    @XmlElement(required = true)
    private String issuerId;

    @XmlElement(required = true)
    public String signingAlgorithm;

    @XmlElement(required = true)
    public Date signingDate;

    @XmlElement(required = true)
    public Date validFrom;

    @XmlElement(required = true)
    public Date validTo;

    @XmlElement(required = true)
    public String levelOfAssurance;

    public String getSignerId() {
        return signerId;
    }

    public void setSignerId(String signerId) {
        this.signerId = signerId;
    }

    public String getSignerDisplayName() {
        return signerDisplayName;
    }

    public void setSignerDisplayName(String signerDisplayName) {
        this.signerDisplayName = signerDisplayName;
    }

    public byte[] getSignerCertificate() {
        return signerCertificate;
    }

    public void setSignerCertificate(byte[] signerCertificate) {
        this.signerCertificate = signerCertificate;
    }

    public String getIssuerId() {
        return issuerId;
    }

    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    public Date getSigningDate() {return signingDate;}

    public void setSigningDate(Date signingDate) {this.signingDate = signingDate;}

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidTo() {
        return validTo;
    }

    public void setValidTo(Date validTo) {
        this.validTo = validTo;
    }

    public String getLevelOfAssurance() {return levelOfAssurance;}

    public void setLevelOfAssurance(String levelOfAssurance) {this.levelOfAssurance = levelOfAssurance;}

}
