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
package be.c4j.ee.security.sso.server.servlet.helper;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.util.TimeUtil;
import be.c4j.ee.security.util.URLUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class OIDCTokenHelper {

    @Inject
    private SSOServerConfiguration ssoServerConfiguration;

    @Inject
    private URLUtil urlUtil;

    @Inject
    private TimeUtil timeUtil;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    public IDTokenClaimsSet defineIDToken(HttpServletRequest httpServletRequest, OctopusSSOUser ssoUser, AuthenticationRequest request, String clientId) {
        Nonce nonce = request.getNonce();

        Issuer iss = new Issuer(urlUtil.determineRoot(httpServletRequest));
        Subject sub = new Subject(ssoUser.getName());
        List<Audience> audList = new Audience(clientId).toSingleAudienceList();

        Date iat = new Date();
        Date exp = timeUtil.addSecondsToDate(ssoServerConfiguration.getSSOAccessTokenTimeToLive(), iat); // TODO Verify how we handle expiration when multiple clients are using the server

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

        claimsSet.setNonce(nonce);
        return claimsSet;
    }


    public IDTokenClaimsSet defineIDToken(HttpServletRequest httpServletRequest, OctopusSSOUser ssoUser, ClientID clientId) {

        Issuer iss = new Issuer(urlUtil.determineRoot(httpServletRequest));
        Subject sub = new Subject(ssoUser.getName());
        List<Audience> audList;
        if (clientId == null) {
            audList = new ArrayList<Audience>();
        } else {

            audList = new Audience(clientId.getValue()).toSingleAudienceList();
        }

        Date iat = new Date();
        Date exp = timeUtil.addSecondsToDate(ssoServerConfiguration.getSSOAccessTokenTimeToLive(), iat); // TODO Verify how we handle expiration when multiple clients are using the server

        return new IDTokenClaimsSet(iss, sub, audList, exp, iat);
    }

    public SignedJWT signIdToken(String clientId, IDTokenClaimsSet claimsSet) {
        SignedJWT idToken;
        try {

            ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(clientId);

            idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());

            idToken.sign(new MACSigner(clientInfo.getIdTokenSecret()));
        } catch (ParseException e) {
            throw new OctopusUnexpectedException(e);
        } catch (KeyLengthException e) {
            throw new OctopusConfigurationException(e.getMessage());  // TODO Better informative message
            // Although, developers should take care that no invalid value can be stored (and thus retrieved here)
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }
        return idToken;
    }

}
