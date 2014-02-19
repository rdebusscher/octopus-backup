package be.c4j.ee.security.event;

import be.c4j.ee.security.model.UserPrincipal;

public class LogoutEvent {

    private UserPrincipal principal;

    public LogoutEvent(UserPrincipal somePrincipal) {
        principal = somePrincipal;
    }

    public UserPrincipal getPrincipal() {
        return principal;
    }
}
