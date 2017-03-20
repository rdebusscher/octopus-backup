/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.c4j.ee.security.view.model;

import be.c4j.ee.security.OctopusJSFSecurityContext;
import be.c4j.ee.security.messages.FacesMessages;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;

import javax.enterprise.inject.Model;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Model
public class LoginBean {

    private String username;

    private String password;

    private boolean remember;

    @Inject
    private OctopusJSFSecurityContext securityContext;

    @Inject
    private FacesMessages facesMessages;

    public void doLogin() throws IOException {
        try {
            ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();

            securityContext.loginWithRedirect((HttpServletRequest) externalContext.getRequest()
                    , externalContext
                    , new UsernamePasswordToken(username, password, remember)
                    , getRootUrl(externalContext));

        } catch (IncorrectCredentialsException e) {
            facesMessages.template("{octopus.invalid_password}").asError().show();

        } catch (UnknownAccountException e) {
            facesMessages.template("{octopus.unknown_username}").asError().show();
        }
    }

    private String getRootUrl(ExternalContext externalContext) {
        return externalContext.getRequestContextPath();
    }

    public void logout() {
        securityContext.logout();
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
