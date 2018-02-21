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
package be.c4j.ee.security.credentials.authentication.microprofile.jwt.client;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.credentials.authentication.jwt.client.JWTClaimsProvider;
import be.c4j.ee.security.credentials.authentication.microprofile.jwt.client.config.MPJWTClientConfig;
import be.c4j.ee.security.credentials.authentication.microprofile.jwt.client.exception.RequiredRSAKeyException;
import be.c4j.ee.security.credentials.authentication.microprofile.jwt.client.exception.UserNameRequiredException;
import be.c4j.ee.security.credentials.authentication.microprofile.jwt.jwk.DefaultKeySelector;
import be.c4j.ee.security.credentials.authentication.microprofile.jwt.jwk.KeySelector;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.util.TimeUtil;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.*;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_INFO;

/**
 *
 */
@ApplicationScoped
public class MPJWTUserToken {

    @Inject
    private UserPrincipal userPrincipal;

    @Inject
    private MPJWTClientConfig mpjwtClientConfig;

    @Inject
    private TimeUtil timeUtil;

    private KeySelector keySelector;

    private ClaimAudienceProvider claimAudienceProvider;

    @PostConstruct
    public void init() {
        KeySelector keySelector = BeanProvider.getContextualReference(KeySelector.class, true);
        if (keySelector != null) {
            this.keySelector = keySelector;
        } else {
            this.keySelector = new DefaultKeySelector();
        }

        claimAudienceProvider = BeanProvider.getContextualReference(ClaimAudienceProvider.class, true);
    }

    public String createJWTUserToken(String kid, String url, JWTClaimsProvider claimsProvider) {

        if (userPrincipal.getId() == null) {
            // Not an authenticated user.
            return null;
        }

        if (userPrincipal.getUserName() == null) {
            throw new UserNameRequiredException();
        }

        // TODO Replace new JWSHeader with the Builder pattern in other parts of the code.
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(defineHeaderKeyId(kid))
                .type(JOSEObjectType.JWT)
                .build();

        JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder();
        claimSetBuilder.audience(defineAudienceClaim(url));

        definePayload(claimSetBuilder);

        Date issueTime = new Date();
        claimSetBuilder.issueTime(issueTime);

        claimSetBuilder.expirationTime(timeUtil.addSecondsToDate(mpjwtClientConfig.getJWTTimeToLive(), issueTime));

        if (claimsProvider != null) {
            Map<String, Object> claims = claimsProvider.defineAdditionalClaims(userPrincipal);

            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                claimSetBuilder.claim(entry.getKey(), entry.getValue());
            }
        }

        SignedJWT signedJWT = new SignedJWT(header, claimSetBuilder.build());

        RSAKey key = keySelector.selectSecretKey(kid, url);
        if (key == null) {
            throw new RequiredRSAKeyException();
        }
        try {
            JWSSigner signer = new RSASSASigner(key);
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }

        return signedJWT.serialize();

    }

    private List<String> defineAudienceClaim(String url) {
        List<String> result = new ArrayList<String>();
        if (claimAudienceProvider != null) {
            result.addAll(claimAudienceProvider.getAudience(url));
        }
        String audienceDefault = mpjwtClientConfig.getTokenAudienceDefault();
        if (StringUtils.hasText(audienceDefault)) {
            result.add(audienceDefault);
        }
        if (result.isEmpty()) {
            throw new OctopusConfigurationException("audience is required for MicroProfile JWT Auth. Parameter 'jwt.token.audience' and ClaimAudienceProvider implementation did not return any value.");
        }
        return result;
    }

    private String defineHeaderKeyId(String kid) {
        String result = kid;
        if (result == null) {
            result = mpjwtClientConfig.getJWTTokenKidDefault();
        }
        if (result == null) {
            result = mpjwtClientConfig.getServerName();
        }
        return result;
    }

    private void definePayload(JWTClaimsSet.Builder claimSetBuilder) {

        claimSetBuilder.jwtID(UUID.randomUUID().toString());
        claimSetBuilder.claim("id", userPrincipal.getId());
        if (userPrincipal.getExternalId() != null) {
            claimSetBuilder.claim(OctopusConstants.EXTERNAL_ID, userPrincipal.getExternalId());
        }
        claimSetBuilder.subject(userPrincipal.getUserName());
        claimSetBuilder.claim("preferred_username", userPrincipal.getUserName());
        claimSetBuilder.claim("name", userPrincipal.getName());
        claimSetBuilder.claim("upn", userPrincipal.getEmail());

        claimSetBuilder.issuer(mpjwtClientConfig.getServerName());

        JSONArray groupsArray = defineGroups();

        claimSetBuilder.claim("groups", groupsArray);
    }

    private JSONArray defineGroups() {
        AuthorizationInfo info = userPrincipal.getUserInfo(AUTHORIZATION_INFO);

        JSONArray groupsArray = new JSONArray();
        if (info.getRoles() != null) {
            // TODO Through the Builder, this is not possible to set.
            groupsArray.addAll(info.getRoles());
        }

        if (info.getStringPermissions() != null) {
            groupsArray.addAll(info.getStringPermissions());
        }

        if (info.getObjectPermissions() != null) {
            for (Permission permission : info.getObjectPermissions()) {

                if (permission instanceof NamedDomainPermission) {
                    NamedDomainPermission namedPermission = (NamedDomainPermission) permission;

                    groupsArray.appendElement(namedPermission.getName());
                } else {
                    if (permission instanceof NamedApplicationRole) {
                        NamedApplicationRole applicationRole = (NamedApplicationRole) permission;
                        groupsArray.appendElement(applicationRole.getRoleName());
                    }
                }
            }
        }
        return groupsArray;
    }

}

