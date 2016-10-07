package be.c4j.ee.security.twostep.totp.view;

import be.c4j.ee.security.context.OctopusSecurityContext;
import be.c4j.ee.security.twostep.totp.token.TOTPToken;

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
@Named(value = "totpBean")
public class TOTPBean {

    @Inject
    private OctopusSecurityContext securityContext;

    private String totpValue;

    public void process() throws IOException {

        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();

        securityContext.loginWithRedirect((HttpServletRequest) externalContext.getRequest()
                , externalContext
                , new TOTPToken(totpValue)
                , null);

    }

    public String getTotpValue() {
        return totpValue;
    }

    public void setTotpValue(String totpValue) {
        this.totpValue = totpValue;
    }
}
