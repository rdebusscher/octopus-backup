/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
 *
 */
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

    public static boolean isInSystemAccountAuthentication() {
        return ThreadContext.get(OctopusRealm.SYSTEM_ACCOUNT_AUTHENTICATION) instanceof OctopusRealm.InSystemAccountAuthentication;

    }
}
