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


    @XmlElement(name="signatures",required = false)
    private Signatures signatures;

    @XmlElement(name="hasDetachedSignature",defaultValue = "false")
    private boolean hasDetachedSignature;

    @XmlElement(name="detachedSignatureData")
    protected byte[] detachedSignatureData;

    @XmlElement(name="validationInfo", required = false)
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
