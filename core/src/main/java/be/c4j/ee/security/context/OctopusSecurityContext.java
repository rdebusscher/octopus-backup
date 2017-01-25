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
package be.c4j.ee.security.context;

import be.c4j.ee.security.exception.SystemAccountActivationException;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import be.c4j.ee.security.systemaccount.SystemAccountPrincipal;
import be.c4j.ee.security.twostep.TwoStepProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;

import javax.enterprise.context.Dependent;
import javax.faces.context.ExternalContext;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.Serializable;

/**
 *
 */
@Dependent
public class OctopusSecurityContext implements Serializable {

    private Subject subject;

    public void prepareForAsyncUsage() {
        subject = SecurityUtils.getSubject();
    }

    public Subject getSubject() {
        Subject result = subject;
        if (subject != null) {

            subject = null;  // So that next calls make a anonymous user or the current Subject associated with the thread.
        } else {
            result = SecurityUtils.getSubject();
        }
        return result;
    }

    public void activateSystemAccount(String systemAccountIdentifier) {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            throw new SystemAccountActivationException();
        } else {
            // TODO Do we need to protect this by checking it is from a trusted place?
            SystemAccountPrincipal accountPrincipal = new SystemAccountPrincipal(systemAccountIdentifier);

            SecurityUtils.getSubject().login(new SystemAccountAuthenticationToken(accountPrincipal));
        }

    }

    public void loginWithRedirect(HttpServletRequest request, ExternalContext externalContext, AuthenticationToken token, String rootUrl) throws IOException {

        SecurityUtils.getSubject().login(token);

        if (SecurityUtils.getSubject().isAuthenticated()) {
            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);

            externalContext.redirect(savedRequest != null ? savedRequest.getRequestUrl() : rootUrl);
        } else {
            // Not authenticated, so we need to startup the Two Step authentication flow.
            TwoStepProvider twoStepProvider = BeanProvider.getContextualReference(TwoStepProvider.class);
            UserPrincipal principal = (UserPrincipal) SecurityUtils.getSubject().getPrincipal();
            twoStepProvider.startSecondStep(request, principal);

            try {
                externalContext.redirect(request.getContextPath() + "/secondStep.xhtml");  // FIXME Parameter
            } catch (IOException e) {
                e.printStackTrace(); // FIXME
                throw e;
            }
        }
    }

    public static boolean isSystemAccount(Object principal) {
        return principal instanceof SystemAccountPrincipal;
    }

}