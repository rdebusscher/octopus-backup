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
package be.c4j.ee.security.twostep.totp.view;

import be.c4j.ee.security.OctopusJSFSecurityContext;
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
    private OctopusJSFSecurityContext securityContext;

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
