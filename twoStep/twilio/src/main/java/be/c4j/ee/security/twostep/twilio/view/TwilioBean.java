package be.c4j.ee.security.twostep.twilio.view;

import be.c4j.ee.security.context.OctopusSecurityContext;
import be.c4j.ee.security.twostep.twilio.token.OTPToken;

import javax.enterprise.context.RequestScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 *
 */
@RequestScoped
@Named
public class TwilioBean {

    @Inject
    private OctopusSecurityContext securityContext;

    private String otpValue;

    public void process() throws IOException {

        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();

        securityContext.loginWithRedirect((HttpServletRequest) externalContext.getRequest()
                , externalContext
                , new OTPToken(otpValue)
                , null);

    }

    public String getOtpValue() {
        return otpValue;
    }

    public void setOtpValue(String otpValue) {
        this.otpValue = otpValue;
    }
}
