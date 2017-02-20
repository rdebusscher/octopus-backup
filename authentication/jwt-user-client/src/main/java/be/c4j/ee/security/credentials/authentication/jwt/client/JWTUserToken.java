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
package be.c4j.ee.security.credentials.authentication.jwt.client;

import be.c4j.ee.security.credentials.authentication.jwt.client.config.JWTClientConfig;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.model.UserPrincipal;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.Date;

/**
 *
 */
@ApplicationScoped
public class JWTUserToken {

    @Inject
    private UserPrincipal userPrincipal;

    @Inject
    private JWTClientConfig jwtClientConfig;

    private JWSSigner signer;

    @PostConstruct
    public void init() {
        try {
            signer = new MACSigner(jwtClientConfig.getMACTokenSecret());
        } catch (KeyLengthException e) {
            // FIXME
            e.printStackTrace();

        }
    }

    public String createJWTUserToken() {
        String payLoad = definePayload();

        // FIXME Algorithm needs to be configurable
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder();
        claimSetBuilder.subject(payLoad);

        claimSetBuilder.issuer("https://c2id.com");
        Date issueTime = new Date();
        claimSetBuilder.issueTime(issueTime);

        claimSetBuilder.expirationTime(addSecondsToDate(2, issueTime));


        SignedJWT signedJWT = new SignedJWT(header, claimSetBuilder.build());

        // Apply the HMAC
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }

        return signedJWT.serialize();

    }

    private static Date addSecondsToDate(int seconds, Date beforeTime) {

        long curTimeInMs = beforeTime.getTime();
        return new Date(curTimeInMs + (seconds * 1000));
    }

    private String definePayload() {
        JSONObject result = new JSONObject();
        try {
            result.put("id", userPrincipal.getId());
            result.put("externalId", userPrincipal.getExternalId());
            result.put("userName", userPrincipal.getUserName());
            result.put("name", userPrincipal.getName());

            AuthorizationInfo info = userPrincipal.getUserInfo("authorizationInfo");

            JSONArray rolesArray = new JSONArray();
            if (info.getRoles() != null) {
                for (String role : info.getRoles()) {
                    rolesArray.put(role);
                }
            }
            result.put("roles", rolesArray);

            JSONArray permissionArray = new JSONArray();
            if (info.getStringPermissions() != null) {
                for (String permission : info.getStringPermissions()) {
                    permissionArray.put(permission);
                }
            }

            if (info.getObjectPermissions() != null) {
                for (Permission permission : info.getObjectPermissions()) {
                    if (permission instanceof WildcardPermission) {
                        // FIXME Is this OK, check if we can other permissions and how we can handle them here.
                        WildcardPermission wildcardPermission = (WildcardPermission) permission;
                        permissionArray.put(wildcardPermission.toString());
                    }
                }
            }

            result.put("permissions", permissionArray);


        } catch (JSONException e) {
            throw new OctopusUnexpectedException(e);
        }
        return result.toString();
    }


}

