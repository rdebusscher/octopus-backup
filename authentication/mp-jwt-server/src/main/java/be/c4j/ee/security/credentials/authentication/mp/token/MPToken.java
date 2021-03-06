/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
 */
package be.c4j.ee.security.credentials.authentication.mp.token;

import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.util.StringUtils;

/**
 *
 */

public class MPToken implements AuthenticationToken, ValidatedAuthenticationToken {

    private MPJWTToken mpjwtToken;
    private String principal;

    public MPToken(MPJWTToken mpjwtToken) {
        this.mpjwtToken = mpjwtToken;
        definePrincipal();
    }

    private void definePrincipal() {
        // Minimum MP-JWT Required Claims
        principal = mpjwtToken.getPreferredUsername();
        if (!StringUtils.hasText(principal)) {
            principal = mpjwtToken.getUpn();
        }
        if (!StringUtils.hasText(principal)) {
            principal = mpjwtToken.getSub();
        }
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return mpjwtToken;
    }

    public String getId() {
        return mpjwtToken.getJti();
    }
}
