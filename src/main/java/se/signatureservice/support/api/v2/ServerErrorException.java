package se.signatureservice.support.api.v2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import java.util.List;

/**
 * Created by philip on 2017-04-13.
 */

@XmlAccessorType(XmlAccessType.FIELD)
public class ServerErrorException extends BaseAPIException {
    public ServerErrorException(String code, Message internationalizedMessage, String detailMessage) {
        super(code, internationalizedMessage,detailMessage);
    }

    public ServerErrorException(String code, List<Message> internationalizedMessages, String detailMessage) {
        super(code, internationalizedMessages,detailMessage);
    }
}
