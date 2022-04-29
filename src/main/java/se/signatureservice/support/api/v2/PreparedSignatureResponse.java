package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="PreparedSignatureResponseType", propOrder = {"signRequest","actionURL","transactionId","profile"})
@XmlAccessorType(XmlAccessType.FIELD)
public class PreparedSignatureResponse {

    @XmlElement(required = true)
    private String signRequest;
    @XmlElement(required = true)
    private String actionURL;
    @XmlElement(required = true)
    private String transactionId;
    @XmlElement(required = true)
    private String profile;

    public String getSignRequest() {
        return signRequest;
    }

    public void setSignRequest(String signRequest) {
        this.signRequest = signRequest;
    }

    public String getActionURL() {
        return actionURL;
    }

    public void setActionURL(String actionURL) {
        this.actionURL = actionURL;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }
}
