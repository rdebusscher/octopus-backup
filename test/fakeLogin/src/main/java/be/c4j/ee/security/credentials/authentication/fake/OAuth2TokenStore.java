package be.c4j.ee.security.credentials.authentication.fake;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.fake.EmailControl;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 *
 */
@ApplicationScoped
public class OAuth2TokenStore {

    @Inject
    private EmailControl emailControl;

    private Map<String, OAuth2User> store = new HashMap<String, OAuth2User>();

    public String retrieveToken(String userParameter) {
        String result = findTokenForEmail(userParameter);
        if (result == null) {
            result = createToken(userParameter);
        }
        return result;
    }

    private String createToken(String userParameter) {
        String token = "Fake" + UUID.randomUUID().toString();
        OAuth2User user = new OAuth2User();
        user.setEmail(userParameter);
        user.setDomain(emailControl.getDomain(userParameter));

        String[] localParts = emailControl.getLocalParts(userParameter);

        user.setFullName(localParts[0] + " " + localParts[1]);
        user.setFirstName(localParts[0]);
        user.setLastName(localParts[1]);
        store.put(token, user);

        return token;
    }

    private String findTokenForEmail(String email) {
        String result = null;
        for (Map.Entry<String, OAuth2User> entry : store.entrySet()) {
            if (entry.getValue().getEmail().equals(email)) {
                result = entry.getKey();
            }
        }
        return result;
    }

    public OAuth2User retrieveUser(String token) {
        return store.get(token);
    }
}