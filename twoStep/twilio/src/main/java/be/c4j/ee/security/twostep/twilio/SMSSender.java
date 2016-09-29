package be.c4j.ee.security.twostep.twilio;

import be.c4j.ee.security.model.UserPrincipal;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class SMSSender {

    public void sendSMS(UserPrincipal userPrincipal, String otpValue) {
        System.out.println(otpValue);
    }
}
