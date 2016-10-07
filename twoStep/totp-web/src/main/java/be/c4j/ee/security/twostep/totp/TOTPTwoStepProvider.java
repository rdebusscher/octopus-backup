package be.c4j.ee.security.twostep.totp;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.twostep.TwoStepAuthenticationInfo;
import be.c4j.ee.security.twostep.TwoStepProvider;
import be.c4j.ee.security.twostep.otp.OTPUserData;
import be.c4j.ee.security.twostep.otp.persistence.OTPUserDataPersistence;
import be.c4j.ee.security.twostep.totp.matcher.TOTPCredentialsMatcher;
import org.apache.shiro.authc.AuthenticationToken;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class TOTPTwoStepProvider implements TwoStepProvider {

    @Inject
    private TOTPHandler handler;

    @Inject
    private OTPUserDataPersistence userDataPersistence;

    @Override
    public void startSecondStep(HttpServletRequest request, UserPrincipal userPrincipal) {
        // Nothing to do
    }

    @Override
    public TwoStepAuthenticationInfo defineAuthenticationInfo(AuthenticationToken token, UserPrincipal userPrincipal) {
        OTPUserData userData = userDataPersistence.retrieveData(userPrincipal);
        return new TwoStepAuthenticationInfo(new TOTPCredentialsMatcher(handler, userData));
    }
}
