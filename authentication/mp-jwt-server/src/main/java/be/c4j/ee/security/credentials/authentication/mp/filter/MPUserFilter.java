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
package be.c4j.ee.security.credentials.authentication.mp.filter;

import be.c4j.ee.security.credentials.authentication.mp.token.MPJWTToken;
import be.c4j.ee.security.credentials.authentication.mp.token.MPToken;
import be.c4j.ee.security.token.IncorrectDataToken;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_HEADER;
import static be.c4j.ee.security.OctopusConstants.BEARER;

/**
 *
 */
public class MPUserFilter extends AuthenticatingFilter implements Initializable {

    private static final List<String> KNOWN_CLAIMS = Arrays.asList("jti", "sub", "upn", "preferred_username", "aud", "iss", "exp", "iat", "groups");

    private MPBearerTokenHandler tokenHandler;

    @Override
    public void init() throws ShiroException {
        tokenHandler = BeanProvider.getContextualReference(MPBearerTokenHandler.class);
    }

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // Same as the noSessionCreate filter. Required also for the SessionHijacking Filter
        request.setAttribute(DefaultSubjectContext.SESSION_CREATION_ENABLED, Boolean.FALSE);
        return super.onPreHandle(request, response, mappedValue);
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader(AUTHORIZATION_HEADER);

        if (token == null) {
            // Authorization header parameter is required.
            return new IncorrectDataToken("Authorization header required");
        }

        String[] parts = token.split(" ");
        if (parts.length != 2) {
            return new IncorrectDataToken("Authorization header value incorrect");
        }
        if (!BEARER.equals(parts[0])) {
            return new IncorrectDataToken("Authorization header value must start with Bearer");
        }

        return createToken(parts[1]);
    }

    private AuthenticationToken createToken(String token) {

        MPJWTToken mpjwtToken = createMPUserToken(token);
        return new MPToken(mpjwtToken);

    }

    private MPJWTToken createMPUserToken(String token) {
        MPJWTToken result;

        // Parse and verify token
        SignedJWT signedJWT = tokenHandler.processToken(token);

        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            result = new MPJWTToken();
            result.setJti(claimsSet.getJWTID());
            result.setSub(claimsSet.getSubject());
            result.setUpn(claimsSet.getStringClaim("upn"));
            result.setPreferredUsername(claimsSet.getStringClaim("preferred_username"));
            result.setAud(claimsSet.getAudience());
            result.setIss(claimsSet.getIssuer());
            if (claimsSet.getExpirationTime() != null) {
                result.setExp(claimsSet.getExpirationTime().getTime());
            }
            if (claimsSet.getIssueTime() != null) {
                result.setIat(claimsSet.getIssueTime().getTime());
            }
            result.setGroups(claimsSet.getStringListClaim("groups"));

            Map<String, Object> additionalClaims = new HashMap<String, Object>();
            for (Map.Entry<String, Object> entry : claimsSet.getClaims().entrySet()) {
                if (!KNOWN_CLAIMS.contains(entry.getKey())) {
                    additionalClaims.put(entry.getKey(), entry.getValue());
                }
            }

            result.setAdditionalClaims(additionalClaims);
        } catch (ParseException e) {
            // TODO Should we log here what kind of issue. Of course don't reply to the end user with the exact issue.
            throw new AuthenticationException("Invalid Authorization Header");

        }

        return result;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }

    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
        ((HttpServletResponse) response).setStatus(401);
        return false; // Stop the filter chain
    }

}
