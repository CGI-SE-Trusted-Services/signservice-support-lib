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
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "MessagesType", propOrder = {
        "message"
})
public class Messages {

    public Messages(){}

    public Messages(List<Message> messages){
        this.message = messages;
    }

    @XmlElement(required = true)
    protected List<Message> message;

    public List<Message> getMessage() {
        if (message == null) {
            message = new ArrayList<Message>();
        }
        return this.message;
    }
}
