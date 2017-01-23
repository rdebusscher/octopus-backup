/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
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
package be.c4j.demo.security.jwt;

import be.c4j.ee.security.credentials.authentication.jwt.CheckJWTClaims;
import be.c4j.ee.security.credentials.authentication.jwt.ClaimCredentialsException;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class DemoCheckJWTClaims implements CheckJWTClaims {
    @Override
    public void areClaimsValid(HttpServletRequest request, Map<String, Object> headerParams, Map<String, Object> claims) {
        String clientAddress = (String) claims.get("clientAddress");
        if (!request.getRemoteHost().equals(clientAddress)) {
            throw new ClaimCredentialsException("JWT token send from wrong origin");
        }
        Date expiration = (Date) claims.get("exp");
        if (expiration.before(new Date())) {
            throw new ClaimCredentialsException("JWT token is expired");
        }

    }
}
