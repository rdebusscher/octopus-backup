package be.c4j.ee.security.authentication;

import javax.enterprise.context.ApplicationScoped;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class ActiveSessionRegistry {

    private Map<String, Object> tokenPrincipalMapping = new HashMap<String, Object>();

    public void startSession(String token, Object principle) {
        tokenPrincipalMapping.put(token, principle);
    }

    public boolean isSessionActive(Object principle) {
        return tokenPrincipalMapping.containsValue(principle);
    }

    public void endSession(String token) {
        tokenPrincipalMapping.remove(token);
    }
}
