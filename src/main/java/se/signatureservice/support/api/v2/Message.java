package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.*;

/**
 * Created by philip on 2017-04-13.
 */
@XmlType(name="MessageType", propOrder = {"text"})
@XmlAccessorType(XmlAccessType.FIELD)
public class Message {

    @XmlAttribute(required = true)
    private String lang;
    @XmlElement(required = true)
    private String text;

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

}
