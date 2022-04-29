package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="AuthenticationServiceType", propOrder = {"authenticationServiceId","displayName","userIdValidator","validationMessages"})
@XmlAccessorType(XmlAccessType.FIELD)
public class AuthenticationService {

    @XmlElement(required = true)
    private String authenticationServiceId;
    @XmlElement(required = true)
    private String displayName;
    @XmlElement()
    private String userIdValidator;
    @XmlElement()
    private Messages validationMessages;

    public String getAuthenticationServiceId() {
        return authenticationServiceId;
    }

    public void setAuthenticationServiceId(String authenticationServiceId) { this.authenticationServiceId = authenticationServiceId;}

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getUserIdValidator() {
        return userIdValidator;
    }

    public void setUserIdValidator(String userIdValidator) {
        this.userIdValidator = userIdValidator;
    }

    public Messages getValidationMessages() { return validationMessages;}

    public void setValidationMessages(Messages validationMessages) { this.validationMessages = validationMessages;}

}
