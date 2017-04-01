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
 */
package be.c4j.ee.security.jwt.filter;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.filter.ErrorInfo;
import be.c4j.ee.security.jwt.JWTClaimsHandler;
import be.c4j.ee.security.jwt.JWTUser;
import be.c4j.ee.security.jwt.config.JWTOperation;
import be.c4j.ee.security.jwt.config.JWTUserConfig;
import be.c4j.ee.security.jwt.encryption.DecryptionHandler;
import be.c4j.ee.security.jwt.encryption.DecryptionHandlerFactory;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_HEADER;

/**
 *
 */

public class JWTAuthenticatingFilter extends AuthenticatingFilter implements Initializable {

    private JWTUserConfig jwtServerConfig;

    private JWTClaimsHandler jwtClaimsHandler;

    private JWTOperation jwtOperation;

    private JWSVerifier verifier;

    private DecryptionHandlerFactory decryptionHandlerFactory;

    @Override
    public void init() throws ShiroException {
        jwtServerConfig = BeanProvider.getContextualReference(JWTUserConfig.class);
        decryptionHandlerFactory = BeanProvider.getContextualReference(DecryptionHandlerFactory.class);

        jwtOperation = jwtServerConfig.getJWTOperation();

        jwtClaimsHandler = BeanProvider.getContextualReference(JWTClaimsHandler.class, true);

        try {
            verifier = new MACVerifier(jwtServerConfig.getHMACTokenSecret());
        } catch (JOSEException e) {
            throw new OctopusConfigurationException(e.getMessage());
        }
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String apiKey = httpServletRequest.getHeader("x-api-key");
        String token = httpServletRequest.getHeader(AUTHORIZATION_HEADER);

        return createToken(apiKey, token);

    }

    private AuthenticationToken createToken(String apiKey, String token) {

        if (token == null) {
            throw new AuthenticationException("Authorization header value incorrect");
        }

        String[] parts = token.split(" ");
        if (parts.length != 2) {
            throw new AuthenticationException("Authorization header value incorrect");
        }
        if (!"Bearer".equals(parts[0])) {
            throw new AuthenticationException("Authorization header value must start with Bearer");
        }

        JWTUser octopusToken = createOctopusToken(apiKey, parts[1]);
        if (octopusToken == null) {
            throw new AuthenticationException("Authentication failed");
        }
        return octopusToken;
    }

    private JWTUser createOctopusToken(String apiKey, String token) {

        JWTUser user = null;

        try {
            // Parse token
            SignedJWT signedJWT;
            if (jwtOperation == JWTOperation.JWT) {
                signedJWT = SignedJWT.parse(token);
            } else {
                signedJWT = decryptToken(apiKey, token);
            }


            if (signedJWT.verify(verifier)) {

                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                if (!verifyClaims(claimsSet)) {
                    throw new AuthenticationException("Invalid token");
                }

                JSONObject jsonObject = getOctopusUserJSONData(claimsSet);

                user = new JWTUser(getString(jsonObject, "name"), getString(jsonObject, "id"));
                user.setUserName(optString(jsonObject, "userName"));
                user.setExternalId(optString(jsonObject, "externalId"));

                assignPermissionsAndRoles(user, jsonObject);

                if (jwtClaimsHandler != null) {

                    user.addUserInfo(jwtClaimsHandler.defineAdditionalUserInfo(user));
                }
            }
        } catch (ParseException e) {
            // TODO Should we log here what kind of issue. Of course don't reply to the end user with the exact issue.
            throw new AuthenticationException("Invalid Authorization Header");
        } catch (JOSEException e) {
            throw new AuthenticationException("Invalid Authorization Header");
        } catch (net.minidev.json.parser.ParseException e) {
            throw new AuthenticationException("Invalid Authorization Header");
        }

        return user;
    }

    private SignedJWT decryptToken(String apiKey, String token) {
        SignedJWT result;
        try {

            DecryptionHandler handler = decryptionHandlerFactory.getDecryptionHandler(jwtServerConfig.getJWEAlgorithm());

            result = handler.doDecryption(apiKey, token);

        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        } catch (ParseException e) {
            throw new OctopusUnexpectedException(e);
        }

        return result;
    }

    private void assignPermissionsAndRoles(JWTUser user, JSONObject jsonObject) {
        JSONArray roles = getJSONArray(jsonObject, "roles");
        user.setRoles(convertToList(roles));

        JSONArray permissions = getJSONArray(jsonObject, "permissions");
        user.setPermissions(convertToList(permissions));
    }

    private JSONObject getOctopusUserJSONData(JWTClaimsSet claimsSet) throws net.minidev.json.parser.ParseException {
        String jsonData = claimsSet.getSubject();

        JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);

        return (JSONObject) parser.parse(jsonData);
    }

    private boolean verifyClaims(JWTClaimsSet claimsSet) {
        Date expirationTime = claimsSet.getExpirationTime();
        boolean result = expirationTime != null && expirationTime.after(new Date());

        if (result && jwtClaimsHandler != null) {
            result = jwtClaimsHandler.claimsAreValid(claimsSet);
        }
        return result;
    }

    private List<String> convertToList(JSONArray array) {
        List<String> result = new ArrayList<String>();
        for (Object anArray : array) {
            result.add(anArray.toString());
        }
        return result;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader(AUTHORIZATION_HEADER);
        if (token != null && !token.isEmpty()) {
            return executeLogin(request, response);
        } else {
            throw new AuthenticationException();
        }
    }

    @Override
    protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
        return false; // Login requests can never happen on REST calls
    }

    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Exception existing) throws ServletException, IOException {
        Exception exception = existing;
        if (exception instanceof AuthenticationException) {
            try {
                ErrorInfo errorInfo = new ErrorInfo("OCT-JWT-USER-001", exception.getMessage());
                sendErrorInfo((HttpServletResponse) response, errorInfo);
                exception = null;
            } catch (Exception e) {
                exception = e;
            }
        }

        OctopusUnauthorizedException unauthorizedException = findOctopusUnauthorizedException(exception);
        if (unauthorizedException != null) {
            ErrorInfo errorInfo = new ErrorInfo("OCT-JWT-USER-011", unauthorizedException.getMessage());
            sendErrorInfo((HttpServletResponse) response, errorInfo);
            exception = null;

        }
        super.cleanup(request, response, exception);
    }

    private void sendErrorInfo(HttpServletResponse httpServletResponse, ErrorInfo errorInfo) throws IOException {
        httpServletResponse.setStatus(401);
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON);
        httpServletResponse.getWriter().append(errorInfo.toJSON());
    }

    private OctopusUnauthorizedException findOctopusUnauthorizedException(Throwable throwable) {
        OctopusUnauthorizedException result = null;
        if (throwable instanceof OctopusUnauthorizedException) {
            result = (OctopusUnauthorizedException) throwable;
        } else {
            if (throwable != null && throwable.getCause() != null) {
                return findOctopusUnauthorizedException(throwable.getCause());
            }
        }
        return result;
    }

    protected String getString(JSONObject jsonObject, String key) {
        return jsonObject.get(key).toString();
    }

    protected String optString(JSONObject jsonObject, String key) {
        if (jsonObject.containsKey(key)) {
            return getString(jsonObject, key);
        } else {
            return null;
        }
    }

    protected JSONArray getJSONArray(JSONObject jsonObject, String key) {
        return (JSONArray) jsonObject.get(key);
    }

}
