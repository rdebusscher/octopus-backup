package be.c4j.demo.security;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.fake.LoginAuthenticationTokenProvider;
import com.github.scribejava.core.model.Token;
import org.apache.shiro.authc.AuthenticationToken;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class DemoLoginAuthenticationTokenProvider implements LoginAuthenticationTokenProvider {

    @Override
    public AuthenticationToken determineAuthenticationToken(String loginData) {

        OAuth2User user;

        if ("test".equals(loginData)) {
            user = testUser();
        } else {
            user = defaultUser();
        }

        return user;
    }

    private OAuth2User defaultUser() {
        OAuth2User result = new OAuth2User();
        result.setFirstName("_Rudy_");
        result.setLastName("_De Busscher_");

        // These are all required
        result.setFullName("_Rudy De Busscher_");
        result.setId("Fake");
        result.setDomain("c4j.be");
        result.setEmail("rudy.debusscher@c4j.be");
        result.setToken(new Token("Fake", ""));
        return result;
    }

    private OAuth2User testUser() {
        OAuth2User result = new OAuth2User();
        result.setFirstName("_test_");
        result.setLastName("_Account_");

        // These are all required
        result.setFullName("_test account_");
        result.setId("Fake");
        result.setDomain("acme.org");
        result.setEmail("test.account@acme.org");
        result.setToken(new Token("Fake", ""));
        return result;
    }
}
