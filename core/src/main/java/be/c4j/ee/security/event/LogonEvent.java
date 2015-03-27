/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.event;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;

public class LogonEvent {

    private AuthenticationToken token;
    private AuthenticationInfo info;

    public LogonEvent(AuthenticationToken someToken, AuthenticationInfo someInfo) {
        token = someToken;
        info = someInfo;
    }

    public AuthenticationToken getToken() {
        return token;
    }

    public AuthenticationInfo getInfo() {
        return info;
    }

}
