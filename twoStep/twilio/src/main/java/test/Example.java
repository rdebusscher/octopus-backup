package test;

import com.twilio.sdk.TwilioRestClient;
import com.twilio.sdk.TwilioRestException;
import com.twilio.sdk.resource.factory.MessageFactory;
import com.twilio.sdk.resource.instance.Message;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class Example {

    // Find your Account Sid and Token at twilio.com/console
    public static final String ACCOUNT_SID = "AC1891f10e57c16e0e6fe6087b7231a897";
    public static final String AUTH_TOKEN = "3af3eaf3db36e665db8fc487de76ac78";

    public static void main(String[] args) throws TwilioRestException {
        TwilioRestClient client = new TwilioRestClient(ACCOUNT_SID, AUTH_TOKEN);

        // Build a filter for the MessageList
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("Body", "Dries vertrekt"));
        params.add(new BasicNameValuePair("To", "+32497807115"));
        params.add(new BasicNameValuePair("From", "+32460200408"));

        MessageFactory messageFactory = client.getAccount().getMessageFactory();
        Message message = messageFactory.create(params);
        System.out.println(message.getSid());
    }

}
