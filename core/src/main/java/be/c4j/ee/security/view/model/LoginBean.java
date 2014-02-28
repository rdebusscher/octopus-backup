package be.c4j.ee.security.view.model;

import org.apache.myfaces.extensions.cdi.jsf.api.Jsf;
import org.apache.myfaces.extensions.cdi.message.api.MessageContext;
import org.apache.myfaces.extensions.cdi.message.api.payload.MessageSeverity;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;

import javax.enterprise.inject.Model;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import java.io.IOException;

@Model
public class LoginBean {

    private String username;

    private String password;

    private boolean remember;

    @Inject
    @Jsf
    private MessageContext messageContext;

    public void doLogin() throws IOException {
        try {
            SecurityUtils.getSubject().login(new UsernamePasswordToken(username, password, remember));
            ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
            SavedRequest savedRequest = WebUtils
                    .getAndClearSavedRequest((ServletRequest) externalContext
                            .getRequest());

            externalContext
                    .redirect(savedRequest != null ? savedRequest.getRequestUrl() : getRootUrl(externalContext));
        } catch (IncorrectCredentialsException e) {
            messageContext.message().text("{octopus.invalid_password}").payload(MessageSeverity.ERROR).add();

        } catch (UnknownAccountException e) {
            messageContext.message().text("{octopus.unknown_username}").payload(MessageSeverity.ERROR).add();
        }
    }

    private String getRootUrl(ExternalContext externalContext) {
        return externalContext.getRequestContextPath();
    }

    public void logout() throws IOException {
        SecurityUtils.getSubject().logout();
        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
        externalContext.redirect(getRootUrl(externalContext));
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String someUsername) {
        username = someUsername;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String somePassword) {
        password = somePassword;
    }

    public boolean isRemember() {
        return remember;
    }

    public void setRemember(boolean someRemember) {
        remember = someRemember;
    }
}
