package be.c4j.ee.security.realm.event;

import be.c4j.ee.security.model.UserPrincipal;

/**
 *
 */
public class ClearAuthorizationCacheEvent {
    private UserPrincipal userPrincipal;

    public ClearAuthorizationCacheEvent(UserPrincipal userPrincipal) {
        this.userPrincipal = userPrincipal;
    }

    public UserPrincipal getUserPrincipal() {
        return userPrincipal;
    }
}
