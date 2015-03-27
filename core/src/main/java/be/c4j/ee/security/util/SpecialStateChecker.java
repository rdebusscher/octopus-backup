package be.c4j.ee.security.util;

import be.c4j.ee.security.event.OctopusAuthenticationListener;
import be.c4j.ee.security.realm.OctopusRealm;
import org.apache.shiro.util.ThreadContext;

/**
 *
 */
public final class SpecialStateChecker {

    private SpecialStateChecker() {
    }

    public static boolean isInAuthorization() {
        return ThreadContext.get(OctopusRealm.IN_AUTHORIZATION_FLAG) instanceof OctopusRealm.InAuthorization;
    }

    public static boolean isInAuthentication() {
        return ThreadContext.get(OctopusRealm.IN_AUTHENTICATION_FLAG) instanceof OctopusRealm.InAuthentication;
    }

    public static boolean isInAuthenticationEvent() {
        return ThreadContext.get(OctopusAuthenticationListener.IN_AUTHENTICATION_EVENT_FLAG) instanceof OctopusAuthenticationListener.InAuthenticationEvent;
    }
}
