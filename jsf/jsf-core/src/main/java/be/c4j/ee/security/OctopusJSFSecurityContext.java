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
package be.c4j.ee.security;

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.context.OctopusSecurityContext;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.logout.LogoutHandler;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.session.SessionUtil;
import be.c4j.ee.security.twostep.TwoStepProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;

import javax.enterprise.inject.Specializes;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 *
 */
@Specializes
public class OctopusJSFSecurityContext extends OctopusSecurityContext {

    @Inject
    private SessionUtil sessionUtil;

    @Inject
    private LogoutHandler logoutHandler;

    @Inject
    private OctopusJSFConfig octopusConfig;

    public void loginWithRedirect(HttpServletRequest request, ExternalContext externalContext, AuthenticationToken token, String rootUrl) throws IOException {

        Subject subject = SecurityUtils.getSubject();

        boolean sessionInvalidate = true;
        if (subject.getPrincipal() != null && !subject.isAuthenticated()) {
            // This is the case for the TwoStep scenario when OTP value is requested.
            // In that case, we shouldn't invalidate the session since we already did it.
            sessionInvalidate = false;
        }
        if (sessionInvalidate) {
            sessionUtil.invalidateCurrentSession(request);
        }
        subject.login(token);

        if (SecurityUtils.getSubject().isAuthenticated()) {
            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);

            externalContext.redirect(savedRequest != null ? savedRequest.getRequestUrl() : rootUrl);
        } else {
            // Not authenticated, so we need to startup the Two Step authentication flow.
            TwoStepProvider twoStepProvider = BeanProvider.getContextualReference(TwoStepProvider.class);
            UserPrincipal principal = (UserPrincipal) SecurityUtils.getSubject().getPrincipal();
            twoStepProvider.startSecondStep(request, principal);

            externalContext.redirect(request.getContextPath() + octopusConfig.getSecondStepPage());
        }
    }


    public void logout() {
        super.logout();

        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
        try {
            externalContext.redirect(this.logoutHandler.getLogoutPage(externalContext));
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }
    }

}
