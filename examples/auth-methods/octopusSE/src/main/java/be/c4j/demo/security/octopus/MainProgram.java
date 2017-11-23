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
package be.c4j.demo.security.octopus;

import be.c4j.ee.security.authentication.octopus.OctopusSEConfiguration;
import be.c4j.ee.security.authentication.octopus.exception.OctopusRetrievalException;
import be.c4j.ee.security.authentication.octopus.requestor.OctopusUserRequestor;
import be.c4j.ee.security.authentication.octopus.requestor.PermissionRequestor;
import be.c4j.ee.security.authentication.octopus.requestor.TokenRequestor;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.PermissionJSONProvider;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.OctopusSSOUserConverter;
import be.c4j.ee.security.sso.client.OpenIdVariableClientData;
import be.c4j.ee.security.sso.rest.DefaultPrincipalUserInfoJSONProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.jackson.JacksonFeature;

import java.net.URISyntaxException;
import java.util.List;

/**
 *
 */

public class MainProgram {


    public static void main(String[] args) {
        OctopusSEConfiguration.prepareConfiguration();

        OctopusSEConfiguration configuration = new OctopusSEConfiguration();

        //Correct PW
        UsernamePasswordToken token = new UsernamePasswordToken("test", "test");

        // Invalid PW
        //UsernamePasswordToken token = new UsernamePasswordToken("test", "wrong");

        TokenResponse tokenResponse = new TokenRequestor(configuration).getToken(token);

        if (!tokenResponse.indicatesSuccess()) {
            TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
            System.out.println(errorResponse.getErrorObject());
            return;
        }

        AccessTokenResponse accessTokenResponse = (AccessTokenResponse) tokenResponse;

        OctopusUserRequestor octopusUserRequestor = new OctopusUserRequestor(configuration, new OctopusSSOUserConverter(),
                new DefaultPrincipalUserInfoJSONProvider(), null);

        OpenIdVariableClientData clientData = new OpenIdVariableClientData();
        OctopusSSOUser octopusSSOUser = null;
        try {
            octopusSSOUser = octopusUserRequestor.getOctopusSSOUser(clientData, accessTokenResponse.getTokens().getBearerAccessToken());
            System.out.println(octopusSSOUser.getFullName());
            System.out.println(octopusSSOUser.getId());
            System.out.println(octopusSSOUser.getUserInfo());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (java.text.ParseException e) {
            e.printStackTrace();
        } catch (OctopusRetrievalException e) {
            e.printStackTrace();
        }

        ClientConfig clientConfiguration = new ClientConfig();
        clientConfiguration.register(JacksonFeature.class);

        PermissionRequestor permissionRequestor = new PermissionRequestor(configuration, null, clientConfiguration, new PermissionJSONProvider());
        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();
        System.out.println(permissions);

        permissions = permissionRequestor.retrieveUserPermissions(octopusSSOUser.getAccessToken());

        System.out.println(permissions);

    }

}