package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="VerifyDocumentResponseType", propOrder = {"signatures","referenceId","reportMimeType","reportData"})
@XmlAccessorType(XmlAccessType.FIELD)
public class VerifyDocumentResponse extends AbstractVerifiedType {

    @XmlElement(name="signatures")
    private Signatures signatures;

    @XmlElement(name="referenceId", required = true)
    private String referenceId;

    @XmlElement(name="reportMimeType")
    private String reportMimeType;

    @XmlElement(name="reportData")
    private byte[] reportData;

    public Signatures getSignatures() {
        return signatures;
    }

    public void setSignatures(Signatures signatures) {
        this.signatures = signatures;
    }

    public String getReferenceId() {
        return referenceId;
    }

    public void setReferenceId(String referenceId) {
        this.referenceId = referenceId;
    }

    public String getReportMimeType() { return reportMimeType; }

    public void setReportMimeType(String reportMimeType) { this.reportMimeType = reportMimeType; }

    public byte[] getReportData() { return reportData; }

    public void setReportData(byte[] reportData) { this.reportData = reportData; }
}
