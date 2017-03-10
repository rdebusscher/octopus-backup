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

import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.rest.DefaultPrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.server.rest.RestUserInfoProvider;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.annotation.security.PermitAll;
import javax.ejb.Singleton;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
@Path("/octopus/sso")
@Singleton
public class OctopusSSOEndpoint {

    private Logger logger = LoggerFactory.getLogger(OctopusSSOEndpoint.class);

    @Inject
    private OctopusSSOUser ssoUser;

    @Inject
    private OctopusConfig octopusConfig;

    @Inject
    private SSOPermissionProvider ssoPermissionProvider;

    @Inject
    private SSOTokenStore tokenStore;

    private RestUserInfoProvider userInfoProvider;

    private PrincipalUserInfoJSONProvider userInfoJSONProvider;

    @PostConstruct
    public void init() {
        userInfoProvider = BeanProvider.getContextualReference(RestUserInfoProvider.class, true);

        userInfoJSONProvider = BeanProvider.getContextualReference(PrincipalUserInfoJSONProvider.class, true);
        if (userInfoJSONProvider == null) {
            userInfoJSONProvider = new DefaultPrincipalUserInfoJSONProvider();
        }
    }

    @Path("/user")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresUser
    public String getUserInfo() {

        // FIXME take into consideration the scope values.
        //When scope contains octopus -> always signed or encrypted. and not JSON by default !!!
        showDebugInfo(ssoUser);

        //
        IDTokenClaimsSet idTokenClaimsSet = tokenStore.getIdTokenByAccessCode(ssoUser.getBearerAccessToken().getValue());

        JWTClaimsSet jwtClaimsSet = null;
        try {
            jwtClaimsSet = idTokenClaimsSet.toJWTClaimsSet();
        } catch (ParseException e) {
            e.printStackTrace();
            // FIXME
        }


        Map<String, Object> info = new HashMap<String, Object>(ssoUser.getUserInfo());
        info.remove("token"); // FIXME Create constant
        info.remove("upstreamToken"); // FIXME Create constant

        if (userInfoProvider != null) {
            info.putAll(userInfoProvider.defineInfo(ssoUser));
        }

        for (Map.Entry<String, Object> entry : jwtClaimsSet.getClaims().entrySet()) {
            info.put(entry.getKey(), entry.getValue());
        }

        return ssoUser.toJSON(info, userInfoJSONProvider);

    }

    private void showDebugInfo(OctopusSSOUser user) {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("Returning user info for  %s (token = %s)", user.getFullName(), user.getAccessToken()));
        }
    }


    @Path("/user/permissions/{applicationName}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresUser
    public Map<String, String> getUserPermissions(@PathParam("applicationName") String application) {
        return fromPermissionsToMap(ssoPermissionProvider.getPermissionsForUserInApplication(application, ssoUser));
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
            result.put(permission.getName(), permission.getWildcardNotation());
        }
        return result;
    }
}
