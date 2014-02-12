package be.c4j.ee.security.view.model;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;

import javax.enterprise.inject.Model;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.servlet.ServletRequest;
import java.io.IOException;

@Model
public class LoginBean {

    private static final String HOME_URL = "/";

    private String username;

    private String password;

    private boolean remember;

    public void doLogin() throws IOException {
        try {
            SecurityUtils.getSubject().login(new UsernamePasswordToken(username, password, remember));
            SavedRequest savedRequest = WebUtils
                    .getAndClearSavedRequest((ServletRequest) FacesContext.getCurrentInstance().getExternalContext()
                                                                          .getRequest());

            FacesContext.getCurrentInstance().getExternalContext()
                        .redirect(savedRequest != null ? savedRequest.getRequestUrl() : HOME_URL);
        } catch (IncorrectCredentialsException e) {
            FacesContext.getCurrentInstance()
                        .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Invalid password, " +
                                "please try again", "Invalid password, please try again"));

        } catch (UnknownAccountException e) {
            FacesContext.getCurrentInstance()
                        .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Unknown user, " +
                                "please try again", "Unknown user, please try again"));

        }
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
