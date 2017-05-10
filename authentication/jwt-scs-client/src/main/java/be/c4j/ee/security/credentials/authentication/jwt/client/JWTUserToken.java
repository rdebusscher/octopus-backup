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

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.credentials.authentication.jwt.client.config.JWTClientConfig;
import be.c4j.ee.security.credentials.authentication.jwt.client.encryption.EncryptionHandler;
import be.c4j.ee.security.credentials.authentication.jwt.client.encryption.EncryptionHandlerFactory;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.jwt.config.JWTOperation;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.util.TimeUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.Date;
import java.util.Map;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_INFO;

/**
 *
 */
@ApplicationScoped
public class JWTUserToken {

    @Inject
    private UserPrincipal userPrincipal;

    @Inject
    private JWTClientConfig jwtClientConfig;

    @Inject
    private EncryptionHandlerFactory encryptionHandlerFactory;

    @Inject
    private TimeUtil timeUtil;

    private JWTOperation jwtOperation;

    private JWSSigner signer;

    @PostConstruct
    public void init() {
        try {
            signer = new MACSigner(jwtClientConfig.getHMACTokenSecret());
            jwtOperation = jwtClientConfig.getJWTOperation();
        } catch (KeyLengthException e) {
            throw new OctopusConfigurationException(e.getMessage());
        }
    }

    public String createJWTUserToken(String apiKey, JWTClaimsProvider claimsProvider) {

        // https://connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt
        String payLoad = definePayload();

        JWSHeader header = new JWSHeader(jwtClientConfig.getJwtSignature().getAlgorithm());

        JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder();
        claimSetBuilder.subject(payLoad);

        Date issueTime = new Date();
        claimSetBuilder.issueTime(issueTime);
        // TODO use jwtUserConfig.getServerName
        // claimSetBuilder.audience()

        claimSetBuilder.expirationTime(timeUtil.addSecondsToDate(jwtClientConfig.getJWTTimeToLive(), issueTime));

        if (claimsProvider != null) {
            Map<String, Object> claims = claimsProvider.defineAdditionalClaims(userPrincipal);

            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                claimSetBuilder.claim(entry.getKey(), entry.getValue());
            }
        }

        SignedJWT signedJWT = new SignedJWT(header, claimSetBuilder.build());

        // Apply the HMAC
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }

        String result;
        if (jwtOperation == JWTOperation.JWE) {
            result = encryptToken(apiKey, signedJWT);
        } else {
            result = signedJWT.serialize();
        }
        return result;

    }

    private String encryptToken(String apiKey, SignedJWT signedJWT) {
        String result;
        try {
            EncryptionHandler encryptionHandler = encryptionHandlerFactory.getEncryptionHandler(jwtClientConfig.getJWEAlgorithm());
            result = encryptionHandler.doEncryption(apiKey, signedJWT);
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }
        return result;
    }

    private String definePayload() {
        JSONObject result = new JSONObject();
        result.put("id", userPrincipal.getId());
        if (userPrincipal.getExternalId() != null) {
            result.put(OctopusConstants.EXTERNAL_ID, userPrincipal.getExternalId());
        }
        result.put("userName", userPrincipal.getUserName());
        result.put("name", userPrincipal.getName());

        AuthorizationInfo info = userPrincipal.getUserInfo(AUTHORIZATION_INFO);

        JSONArray rolesArray = new JSONArray();
        if (info.getRoles() != null) {
            rolesArray.addAll(info.getRoles());
        }
        result.put("roles", rolesArray);

        JSONArray permissionArray = new JSONArray();
        if (info.getStringPermissions() != null) {
            permissionArray.addAll(info.getStringPermissions());
        }

        if (info.getObjectPermissions() != null) {
            for (Permission permission : info.getObjectPermissions()) {
                if (permission instanceof WildcardPermission) {
                    // FIXME Is this OK, check if we can add other permissions and how we can handle them here.
                    WildcardPermission wildcardPermission = (WildcardPermission) permission;
                    permissionArray.add(wildcardPermission.toString());
                }
            }
        }

        result.put("permissions", permissionArray);

        return result.toJSONString();
    }


}

