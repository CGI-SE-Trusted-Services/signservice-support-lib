package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.*;
import java.util.Arrays;
import java.util.List;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="AbstractAPIExceptionType", propOrder = {"code","messages","detailMessage"})
@XmlAccessorType(XmlAccessType.FIELD)
public class BaseAPIException extends Exception {

    @XmlElement(name="code",required = true)
    private String code;

    @XmlElement(name="messages",required = true)
    private Messages messages;

    @XmlElement(name="detailMessage",required = true)
    private String detailMessage;

    public BaseAPIException(){

    }

    public BaseAPIException(String code, Message messages, String detailMessage) {
        super(detailMessage);
        this.code = code;
        this.setMessages(new Messages(Arrays.asList(messages)));
        this.detailMessage = detailMessage;
    }

    public BaseAPIException(String code, List<Message> messages, String detailMessage) {
        super(detailMessage);
        this.code = code;
        assert messages.size() > 0 : "Error at least on internationalized message must exist in fault";
        this.setMessages(new Messages(messages));
        this.detailMessage = detailMessage;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public Messages getMessages() {
        return messages;
    }

    public void setMessages(Messages messages) {
        this.messages = messages;
    }

    public String getDetailMessage() {
        return detailMessage;
    }

    public void setDetailMessage(String detailMessage) {
        this.detailMessage = detailMessage;
    }

    @XmlTransient
    @Override
    public String getMessage() {
        return super.getMessage();
    }
}
