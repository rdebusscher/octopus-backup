package be.c4j.ee.security.sso.server.url;

import be.c4j.ee.security.url.ProgrammaticURLProtectionProvider;

import javax.enterprise.context.ApplicationScoped;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class SSOServerURLProtectionProvider implements ProgrammaticURLProtectionProvider {


    @Override
    public Map<String, String> getURLEntriesToAdd() {
        Map<String, String> result = new HashMap<String, String>();
        // For the rest authentication
        result.put("/data/octopus/rest/user","anon");
        // For the rest endpoints retrieving user info / permissions
        result.put("/data/octopus/sso/permissions/*","anon");
        result.put("/data/octopus/**","ssoFilter, user");
        //URL Which triggers Login
        result.put("/octopus/**","ssoAuthFilter, user");

        return result;
    }
}
