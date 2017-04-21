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
package be.c4j.ee.security.sso.client.logout;

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.logout.LogoutURLProcessor;
import be.c4j.ee.security.sso.client.JWSAlgorithmFactory;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.util.TimeUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Date;

/**
 *
 */
@ApplicationScoped
public class SSOClientLogoutURLProcessor implements LogoutURLProcessor {

    @Inject
    private OctopusSSOClientConfiguration ssoClientConfiguration;

    @Inject
    private JWSAlgorithmFactory jwsAlgorithmFactory;

    @Inject
    private TimeUtil timeUtil;

    private JWSAlgorithm algorithm;

    private Issuer issuer;
    private Subject subject;

    @PostConstruct
    public void init() {
        algorithm = jwsAlgorithmFactory.determineOptimalAlgorithm(ssoClientConfiguration.getSSOClientSecret());
        issuer = new Issuer(ssoClientConfiguration.getSSOClientId());
        subject = new Subject(ssoClientConfiguration.getSSOClientId());
    }

    @Override
    public String postProcessLogoutUrl(String logoutURL) {

        Date iat = new Date();
        Date exp = timeUtil.addSecondsToDate(2, iat); // TODO Config parameter for time?
        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(issuer, subject, new ArrayList<Audience>(), exp, iat);

        SignedJWT idToken;
        try {
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(algorithm);
            headerBuilder.customParam("clientId", ssoClientConfiguration.getSSOClientId());
            idToken = new SignedJWT(headerBuilder.build(), claimsSet.toJWTClaimsSet());

            idToken.sign(new MACSigner(ssoClientConfiguration.getSSOClientSecret()));
        } catch (ParseException e) {
            throw new OctopusUnexpectedException(e);
        } catch (JOSEException e) {
            throw new OctopusUnexpectedException(e);
        }

        LogoutRequest logoutRequest = new LogoutRequest(null, idToken);
        return logoutURL + "?" + logoutRequest.toQueryString();

    }
}
