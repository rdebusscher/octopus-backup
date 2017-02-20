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

import be.c4j.ee.security.jwt.JWTUser;
import be.c4j.ee.security.jwt.config.JWTServerConfig;
import be.c4j.ee.security.token.IncorrectDataToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public class JWTAuthenticatingFilter extends AuthenticatingFilter implements Initializable {

    private JWTServerConfig jwtServerConfig;

    private JWSVerifier verifier;

    @Override
    public void init() throws ShiroException {
        jwtServerConfig = BeanProvider.getContextualReference(JWTServerConfig.class);
        try {
            verifier = new MACVerifier(jwtServerConfig.getMACTokenSecret());
        } catch (JOSEException e) {
            // FIXME
            e.printStackTrace();
        }
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String apiKey = httpServletRequest.getHeader("x-api-key");
        String token = httpServletRequest.getHeader("Authorization");

        return createOctopusUser(httpServletRequest, apiKey, token);

    }

    private AuthenticationToken createOctopusUser(HttpServletRequest request, String apiKey, String token) {

        String[] parts = token.split(" ");
        if (parts.length != 2) {
            return new IncorrectDataToken("Authorization header value incorrect");
        }
        if (!"Bearer".equals(parts[0])) {
            return new IncorrectDataToken("Authorization header value must start with Bearer");
        }

        JWTUser octopusToken = createOctopusToken(request, apiKey, parts[1]);
        if (octopusToken == null) {
            return new IncorrectDataToken("Authentication failed");
        }
        return octopusToken;
    }

    private JWTUser createOctopusToken(HttpServletRequest request, String apiKey, String token) {

        JWTUser user = null;

        try {
            // Parse token
            SignedJWT signedJWT = SignedJWT.parse(token);

            if (signedJWT.verify(verifier)) {

                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                String jsonData = claimsSet.getSubject();

                JSONObject jsonObject = new JSONObject(jsonData);

                user = new JWTUser(jsonObject.getString("name"), jsonObject.getString("id"));
                user.setUserName(jsonObject.optString("userName"));

                JSONArray roles = jsonObject.getJSONArray("roles");
                user.setRoles(convertToList(roles));

                JSONArray permissions = jsonObject.getJSONArray("permissions");
                user.setPermissions(convertToList(permissions));

            }
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (JSONException e) {
            e.printStackTrace();
        }

        return user;
    }

    private List<String> convertToList(JSONArray array) throws JSONException {
        List<String> result = new ArrayList<String>();
        int length = array.length();
        for (int i = 0; i < length; i++) {
            result.add(array.getString(i));
        }
        return result;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader("Authorization");
        if (token != null && !token.isEmpty()) {
            return executeLogin(request, response);
        } else {
            throw new AuthenticationException();
            //return false;
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
                ((HttpServletResponse) response).setStatus(401);
                exception = null;
            } catch (Exception e) {
                exception = e;
            }
        }
        super.cleanup(request, response, exception);
    }
}
