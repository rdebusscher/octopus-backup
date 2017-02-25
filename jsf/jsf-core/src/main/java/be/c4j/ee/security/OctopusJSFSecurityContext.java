package be.c4j.ee.security;

import be.c4j.ee.security.context.OctopusSecurityContext;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.logout.LogoutHandler;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.session.SessionUtil;
import be.c4j.ee.security.twostep.TwoStepProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
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

    public void loginWithRedirect(HttpServletRequest request, ExternalContext externalContext, AuthenticationToken token, String rootUrl) throws IOException {

        sessionUtil.invalidateCurrentSession(request);

        SecurityUtils.getSubject().login(token);

        if (SecurityUtils.getSubject().isAuthenticated()) {
            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);

            externalContext.redirect(savedRequest != null ? savedRequest.getRequestUrl() : rootUrl);
        } else {
            // Not authenticated, so we need to startup the Two Step authentication flow.
            TwoStepProvider twoStepProvider = BeanProvider.getContextualReference(TwoStepProvider.class);
            UserPrincipal principal = (UserPrincipal) SecurityUtils.getSubject().getPrincipal();
            twoStepProvider.startSecondStep(request, principal);

            externalContext.redirect(request.getContextPath() + "/secondStep.xhtml");  // FIXME Parameter
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
