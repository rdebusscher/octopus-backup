/*
 * Copyright 2014-2018 Rudy De Busscher (www.c4j.be)
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

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.filter.ErrorInfo;
import be.c4j.ee.security.jwt.JWKManager;
import be.c4j.ee.security.jwt.JWTClaimsHandler;
import be.c4j.ee.security.jwt.SCSUser;
import be.c4j.ee.security.jwt.config.JWTOperation;
import be.c4j.ee.security.jwt.config.MappingSystemAccountToApiKey;
import be.c4j.ee.security.jwt.config.SCSConfig;
import be.c4j.ee.security.jwt.encryption.DecryptionHandler;
import be.c4j.ee.security.jwt.encryption.DecryptionHandlerFactory;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.permission.PermissionJSONProvider;
import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import be.c4j.ee.security.systemaccount.SystemAccountPrincipal;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import javax.inject.Inject;
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
import java.util.Map;

import static be.c4j.ee.security.OctopusConstants.*;
import static be.c4j.ee.security.shiro.OctopusSessionStorageEvaluator.NO_STORAGE;

/**
 *
 */

public class SCSAuthenticatingFilter extends AuthenticatingFilter implements Initializable {

    @Inject
    private SCSConfig jwtServerConfig;

    private JWTClaimsHandler jwtClaimsHandler;

    private JWTOperation jwtOperation;

    @Inject
    private DecryptionHandlerFactory decryptionHandlerFactory;

    @Inject
    private JWKManager jwkManager;

    @Inject
    private MappingSystemAccountToApiKey mappingSystemAccountToApiKey;

    private PermissionJSONProvider permissionJSONProvider;

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // Same as the noSessionCreate filter. Required also for the SessionHijacking Filter
        request.setAttribute(DefaultSubjectContext.SESSION_CREATION_ENABLED, Boolean.FALSE);
        return super.onPreHandle(request, response, mappedValue);
    }

    @Override
    public void init() throws ShiroException {
        BeanProvider.injectFields(this);

        jwtOperation = jwtServerConfig.getJWTOperation();

        jwtClaimsHandler = BeanProvider.getContextualReference(JWTClaimsHandler.class, true);

        // The PermissionJSONProvider is located in a JAR With CDI support.
        // Developer must have to opportunity to define a custom version.
        // So first look at CDI class. If not found, use the default.
        permissionJSONProvider = BeanProvider.getContextualReference(PermissionJSONProvider.class, true);
        if (permissionJSONProvider == null) {
            permissionJSONProvider = new PermissionJSONProvider();
        }

    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String apiKey = httpServletRequest.getHeader(X_API_KEY);
        String token = httpServletRequest.getHeader(AUTHORIZATION_HEADER);

        AuthenticationToken result = createToken(apiKey, token);
        request.setAttribute(NO_STORAGE, Boolean.TRUE);
        return result;

    }

    private AuthenticationToken createToken(String apiKey, String token) {

        if (token == null) {
            throw new AuthenticationException("Authorization header value incorrect");
        }

        String[] parts = token.split(" ");
        if (parts.length != 2) {
            throw new AuthenticationException("Authorization header value incorrect");
        }
        if (!BEARER.equals(parts[0])) {
            throw new AuthenticationException("Authorization header value must start with Bearer");
        }

        AuthenticationToken octopusToken = createOctopusToken(apiKey, parts[1]);
        if (octopusToken == null) {
            throw new AuthenticationException("Authentication failed");
        }
        return octopusToken;
    }

    private AuthenticationToken createOctopusToken(String apiKey, String token) {

        AuthenticationToken result = null;

        // apiKey means -> SystemAccount OR Encrypted userAccount.

        if (apiKey != null) {
            if (mappingSystemAccountToApiKey.isSystemAccountUsageActive()) {
                result = createSystemAccountToken(apiKey, token);
            }
        }

        if (result == null) {
            result = createJWTUserToken(apiKey, token);
        }
        return result;
    }

    private SystemAccountAuthenticationToken createSystemAccountToken(String apiKey, String token) {
        SystemAccountAuthenticationToken result = null;
        if (!jwkManager.existsApiKey(apiKey)) {
            return null;
        }

        List<String> accountList = mappingSystemAccountToApiKey.getAccountList(apiKey);
        if (accountList == null || accountList.isEmpty()) {
            return null;
        }

        try {
            // Parse token
            SignedJWT signedJWT;
            if (jwtOperation == JWTOperation.JWT) {
                signedJWT = SignedJWT.parse(token);
            } else {
                signedJWT = decryptToken(apiKey, token);
            }

            JWSVerifier verifier;
            try {
                verifier = new RSASSAVerifier((RSAKey) jwkManager.getJWKForApiKey(apiKey));
            } catch (JOSEException e) {
                throw new OctopusConfigurationException(e.getMessage());
            }

            if (signedJWT.verify(verifier)) {
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                // TODO Show some error in  the log that makes it easier to determine why the token was invalid
                if (!apiKey.equals(signedJWT.getHeader().getKeyID())) {
                    throw new AuthenticationException("Invalid token");
                }
                if (!verifyClaims(claimsSet)) {
                    throw new AuthenticationException("Invalid token");
                }

                if (!accountList.contains(signedJWT.getJWTClaimsSet().getSubject())) {
                    throw new AuthenticationException("Invalid token");
                }

                // TODO Since we are using systemAccount.properties file to see if systemAccount is allowed to connect.
                // we should add the verification if the correct kid is used (matches the one in the properties file)
                List<String> audience = signedJWT.getJWTClaimsSet().getAudience();
                if (!audience.contains(jwtServerConfig.getServerName())) {
                    throw new AuthenticationException("Invalid token");
                }

                result = new SystemAccountAuthenticationToken(new SystemAccountPrincipal(signedJWT.getJWTClaimsSet().getSubject()));

            }
        } catch (ParseException e) {
            // TODO Should we log here what kind of issue. Of course don't reply to the end user with the exact issue.
            throw new AuthenticationException("Invalid Authorization Header");
        } catch (JOSEException e) {
            throw new AuthenticationException("Invalid Authorization Header");
        }
        return result;
    }

    private SCSUser createJWTUserToken(String apiKey, String token) {
        SCSUser result = null;
        try {
            JWSVerifier verifier;
            try {
                verifier = new MACVerifier(jwtServerConfig.getHMACTokenSecret());
            } catch (JOSEException e) {
                throw new OctopusConfigurationException(e.getMessage());
            }

            // Parse token
            SignedJWT signedJWT;
            // apiKey == null is this too strict ?? Meaning when using apiKey for a ClientCall must it be encrypted ??
            if (jwtOperation == JWTOperation.JWT && apiKey == null) {
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

                result = new SCSUser(getString(jsonObject, "name"), getString(jsonObject, "id"));
                result.setUserName(optString(jsonObject, "userName"));
                result.setExternalId(optString(jsonObject, OctopusConstants.EXTERNAL_ID));

                assignPermissionsAndRoles(result, jsonObject);

                if (jwtClaimsHandler != null) {

                    result.addUserInfo(jwtClaimsHandler.defineAdditionalUserInfo(result));
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
        return result;
    }

    private SignedJWT decryptToken(String apiKey, String token) {
        SignedJWT result;
        try {

            DecryptionHandler handler = decryptionHandlerFactory.getDecryptionHandler(jwtServerConfig.getJWEAlgorithm());
            result = handler.doDecryption(apiKey + "_enc", token);

        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        } catch (ParseException e) {
            throw new OctopusUnexpectedException(e);
        }

        return result;
    }

    private void assignPermissionsAndRoles(SCSUser user, JSONObject jsonObject) {
        JSONArray roles = getJSONArray(jsonObject, "roles");
        user.setRoles(convertToList(roles));

        JSONArray permissions = getJSONArray(jsonObject, "permissions");
        user.setPermissions(convertToList(permissions));

        JSONObject namedPermissions = (JSONObject) jsonObject.get("namedPermissions");
        List<NamedPermission> namedDomainPermissions = convertToNamedPermissionList(namedPermissions);

        user.setNamedPermissions(namedDomainPermissions);
    }

    private List<NamedPermission> convertToNamedPermissionList(JSONObject namedPermissions) {
        List<NamedPermission> result = new ArrayList<NamedPermission>();
        for (Map.Entry<String, Object> entry : namedPermissions.entrySet()) {
            result.add(permissionJSONProvider.readValue(entry.getKey(), entry.getValue().toString()));
        }
        return result;
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
                ErrorInfo errorInfo = new ErrorInfo("OCT-JWT-SCS-001", exception.getMessage());
                sendErrorInfo((HttpServletResponse) response, errorInfo);
                exception = null;
            } catch (Exception e) {
                exception = e;
            }
        }

        OctopusUnauthorizedException unauthorizedException = findOctopusUnauthorizedException(exception);
        if (unauthorizedException != null) {
            ErrorInfo errorInfo = new ErrorInfo("OCT-JWT-SCS-011", unauthorizedException.getMessage());
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
