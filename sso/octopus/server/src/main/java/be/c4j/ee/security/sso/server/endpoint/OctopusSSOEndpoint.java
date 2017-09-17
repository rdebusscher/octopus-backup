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
package be.c4j.ee.security.sso.server.endpoint;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.PermissionJSONProvider;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.OctopusSSOUserConverter;
import be.c4j.ee.security.sso.rest.DefaultPrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.config.UserEndpointEncoding;
import be.c4j.ee.security.sso.server.store.OIDCStoreData;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import be.c4j.ee.security.util.TimeUtil;
import be.c4j.ee.security.util.URLUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.annotation.security.PermitAll;
import javax.ejb.Singleton;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.*;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_HEADER;
import static com.nimbusds.openid.connect.sdk.claims.UserInfo.SUB_CLAIM_NAME;

/**
 *
 */
@Path("/octopus/sso")
@Singleton
public class OctopusSSOEndpoint {

    private static final List<String> KEYS = Arrays.asList(OctopusConstants.EMAIL, OctopusConstants.TOKEN, "rememberMe");

    private Logger logger = LoggerFactory.getLogger(OctopusSSOEndpoint.class);

    @Inject
    private OctopusSSOUser ssoUser;

    @Inject
    private OctopusConfig octopusConfig;

    @Inject
    private SSOServerConfiguration ssoServerConfiguration;

    @Inject
    private SSOPermissionProvider ssoPermissionProvider;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Inject
    private OctopusSSOUserConverter octopusSSOUserConverter;

    @Inject
    private TimeUtil timeUtil;

    @Inject
    private URLUtil urlUtil;

    private PrincipalUserInfoJSONProvider userInfoJSONProvider;

    private PermissionJSONProvider permissionJSONProvider;

    @PostConstruct
    public void init() {
        // The PermissionJSONProvider is located in a JAR With CDI support.
        // Developer must have to opportunity to define a custom version.
        // So first look at CDI class. If not found, use the default.

        permissionJSONProvider = BeanProvider.getContextualReference(PermissionJSONProvider.class, true);
        if (permissionJSONProvider == null) {
            permissionJSONProvider = new PermissionJSONProvider();
        }

        userInfoJSONProvider = BeanProvider.getContextualReference(PrincipalUserInfoJSONProvider.class, true);
        if (userInfoJSONProvider == null) {
            userInfoJSONProvider = new DefaultPrincipalUserInfoJSONProvider();
        }
    }

    @Path("/user")
    @POST
    @RequiresUser
    public Response getUserInfoPost(@HeaderParam(AUTHORIZATION_HEADER) String authorizationHeader, @Context UriInfo uriDetails) {
        return getUserInfo(authorizationHeader, uriDetails);
    }

    @Path("/user")
    @GET
    @RequiresUser
    public Response getUserInfo(@HeaderParam(AUTHORIZATION_HEADER) String authorizationHeader, @Context UriInfo uriDetails) {

        //When scope contains octopus -> always signed or encrypted. and not JSON by default !!!
        showDebugInfo(ssoUser);

        String accessToken = getAccessToken(authorizationHeader);
        //

        OIDCStoreData oidcStoreData = tokenStore.getOIDCDataByAccessToken(accessToken);
        IDTokenClaimsSet idTokenClaimsSet = oidcStoreData.getIdTokenClaimsSet();

        JWTClaimsSet jwtClaimsSet;
        try {
            if (idTokenClaimsSet == null) {
                // There was no scope openid specified. But for convenience we define a minimal response
                JSONObject json = new JSONObject();
                json.put(SUB_CLAIM_NAME, ssoUser.getUserName());

                json.put("iss", urlUtil.determineRoot(uriDetails.getBaseUri()));

                Date iat = new Date();
                Date exp = timeUtil.addSecondsToDate(ssoServerConfiguration.getSSOAccessTokenTimeToLive(), iat); // TODO Verify how we handle expiration when multiple clients are using the server

                json.put("exp", exp.getTime());

                jwtClaimsSet = JWTClaimsSet.parse(json);
            } else {
                jwtClaimsSet = idTokenClaimsSet.toJWTClaimsSet();
            }
        } catch (ParseException e) {
            throw new OctopusUnexpectedException(e);
        } catch (java.text.ParseException e) {
            throw new OctopusUnexpectedException(e);
        }

        UserEndpointEncoding endpointEncoding = ssoServerConfiguration.getUserEndpointEncoding();

        if (endpointEncoding == UserEndpointEncoding.JWE) {
            throw new OctopusConfigurationException("SSO server user endpoint coding JWE is not yet suported");
            // TODO Support for JWE
        }

        UserInfo userInfo = octopusSSOUserConverter.fromIdToken(jwtClaimsSet);

        Scope scope = oidcStoreData.getAccessToken().getScope();
        if (scope != null && scope.contains("octopus")) {

            userInfo.putAll(octopusSSOUserConverter.asClaims(ssoUser, userInfoJSONProvider));

            endpointEncoding = UserEndpointEncoding.JWS;
        }

        if (scope != null && scope.contains("email")) {

            userInfo.setEmailAddress(ssoUser.getEmail());
        }

        if (scope != null && scope.contains("userinfo")) {


            Map<String, Object> filteredInfo = new HashMap<String, Object>();
            for (Map.Entry<String, Object> entry : ssoUser.getUserInfo().entrySet()) {
                if (!KEYS.contains(entry.getKey())) {
                    filteredInfo.put(entry.getKey(), entry.getValue());
                }
            }
            userInfo.putAll(filteredInfo);
        }

        // TODO Extension so that we can handle custom scopes.

        Response.ResponseBuilder builder = Response.status(Response.Status.OK);

        // Is this endpoint specified in OpenIdConnect and is NONE allowed?
        if (endpointEncoding == UserEndpointEncoding.NONE) {
            builder.type(CommonContentTypes.APPLICATION_JSON.toString());
            builder.entity(userInfo.toJSONObject().toJSONString());
        }

        if (endpointEncoding == UserEndpointEncoding.JWS) {
            buildResponsePayload(builder, uriDetails, oidcStoreData, userInfo);
        }

        return builder.build();

    }

    private void buildResponsePayload(Response.ResponseBuilder builder, UriInfo uriDetails, OIDCStoreData oidcStoreData, UserInfo userInfo) {
        builder.type(CommonContentTypes.APPLICATION_JWT.toString());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder();

        claimSetBuilder.issuer(uriDetails.getRequestUri().toASCIIString());
        claimSetBuilder.expirationTime(timeUtil.addSecondsToDate(2, new Date()));
        // Spec defines that we need also aud, but this is already set from idTokenClaimSet

        JSONObject jsonObject = userInfo.toJSONObject();
        for (String key : jsonObject.keySet()) {
            if ("aud".equals(key)) {
                // due to octopusSSOUserConverter.fromIdToken(jwtClaimsSet); earlier, there was a conversion from jwtClaimsSet to JSonObject
                // Which converted the Audience List to a single String.  If we don't put it in the correct type again, the new SignedJWT 3 statements further on
                // Will fail on the audience and leave it out from the SignedJWT.
                claimSetBuilder.claim(key, Collections.singletonList(jsonObject.get(key)));
            } else {
                claimSetBuilder.claim(key, jsonObject.get(key));
            }
        }

        SignedJWT signedJWT = new SignedJWT(header, claimSetBuilder.build());

        // Apply the HMAC
        ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(oidcStoreData.getClientId().getValue());
        try {
            signedJWT.sign(new MACSigner(clientInfo.getIdTokenSecretByte()));
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }

        builder.entity(signedJWT.serialize());
    }

    private String getAccessToken(String authorizationHeader) {
        return authorizationHeader.split(" ")[1];
    }

    private void showDebugInfo(OctopusSSOUser user) {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("Returning user info for  %s (cookie token = %s)", user.getFullName(), user.getCookieToken()));
        }
    }


    @Path("/user/permissions/{applicationName}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresUser
    public Map<String, String> getUserPermissions(@PathParam("applicationName") String application, @Context HttpServletRequest httpServletRequest) {
        Scope scope = (Scope) httpServletRequest.getAttribute(Scope.class.getName());
        if (scope != null && scope.contains("octopus")) {
            return fromPermissionsToMap(ssoPermissionProvider.getPermissionsForUserInApplication(application, ssoUser));
        } else {
            return null;
        }
    }

    @Path("/permissions/{applicationName}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @PermitAll
    public Map<String, String> getPermissions(@PathParam("applicationName") String application) {
        // Return the list of all permissions !!!
        // For the moment anon access!!
        return fromPermissionsToMap(ssoPermissionProvider.getPermissionsForApplication(application));
    }

    private Map<String, String> fromPermissionsToMap(List<NamedDomainPermission> permissions) {
        Map<String, String> result = new HashMap<String, String>();
        for (NamedDomainPermission permission : permissions) {
            result.put(permission.getName(), permissionJSONProvider.writeValue(permission));
        }
        return result;
    }
}
