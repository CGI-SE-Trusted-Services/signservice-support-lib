package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="AbstractVerifiedType",  propOrder = {"verifies","verificationErrorCode","verificationErrorMessages"})
@XmlAccessorType(XmlAccessType.FIELD)
public class AbstractVerifiedType {

    @XmlElement(name="verifies",required = true)
    private boolean verifies;
    @XmlElement(name="verificationErrorCode")
    private Integer verificationErrorCode;
    @XmlElement(name="verificationErrorMessages")
    private Messages verificationErrorMessages;

    public boolean getVerifies() {
        return verifies;
    }

    public boolean isVerifies() {
        return verifies;
    }

    public void setVerifies(boolean verifies) {
        this.verifies = verifies;
    }

    public Integer getVerificationErrorCode() {
        return verificationErrorCode;
    }

    public void setVerificationErrorCode(Integer verificationErrorCode) {
        this.verificationErrorCode = verificationErrorCode;
    }

    public Messages getVerificationErrorMessages() {
        return verificationErrorMessages;
    }

    public void setVerificationErrorMessages(Messages messages) {
        this.verificationErrorMessages = messages;
    }

}
