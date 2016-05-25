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
package be.c4j.ee.security.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * AuthenticationToken which can be used when insufficient/incorrect data was available on the requestHeader. Used in the OAuth2 and JWT authentication filters.
 */
public class IncorrectDataToken implements AuthenticationToken {

    private String message;

    public IncorrectDataToken(String message) {
        this.message = message;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("IncorrectDataToken{");
        sb.append("message='").append(message).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
