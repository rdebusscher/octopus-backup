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
package be.c4j.ee.security.authentication.octopus.requestor;

import be.c4j.ee.security.authentication.octopus.OctopusSEConfiguration;
import be.c4j.ee.security.authentication.octopus.debug.CorrelationCounter;
import be.c4j.ee.security.authentication.octopus.exception.OctopusRetrievalException;
import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.OctopusSSOUserConverter;
import be.c4j.ee.security.sso.client.OpenIdVariableClientData;
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 *
 */

public class OctopusUserRequestor extends AbstractRequestor {

    private OctopusSSOUserConverter octopusSSOUserConverter;

    private PrincipalUserInfoJSONProvider userInfoJSONProvider;

    public OctopusUserRequestor(OctopusSEConfiguration configuration, OctopusSSOUserConverter octopusSSOUserConverter, PrincipalUserInfoJSONProvider userInfoJSONProvider) {
        super(configuration);
        this.octopusSSOUserConverter = octopusSSOUserConverter;
        this.userInfoJSONProvider = userInfoJSONProvider;
    }

    public OctopusSSOUser getOctopusSSOUser(OpenIdVariableClientData variableClientData, BearerAccessToken accessToken) throws URISyntaxException, ParseException, JOSEException, java.text.ParseException, OctopusRetrievalException {
        UserInfoRequest infoRequest = new UserInfoRequest(new URI(configuration.getUserInfoEndpoint()), accessToken);

        HTTPRequest httpRequest = infoRequest.toHTTPRequest();

        int correlationId = -1;
        if (configuration.showDebugFor().contains(Debug.SSO_REST)) {
            correlationId = CorrelationCounter.VALUE.getAndIncrement();
            showRequest(correlationId, httpRequest);
        }

        HTTPResponse response;
        try {
            response = httpRequest.send();
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);

        }
        if (configuration.showDebugFor().contains(Debug.SSO_REST)) {
            showResponse(correlationId, response);
        }

        UserInfoResponse userInfoResponse = UserInfoResponse.parse(response);

        if (!userInfoResponse.indicatesSuccess()) {
            UserInfoErrorResponse errorResponse = (UserInfoErrorResponse) userInfoResponse;
            throw new OctopusRetrievalException(errorResponse.getErrorObject());

        }

        UserInfoSuccessResponse successInfoResponse = (UserInfoSuccessResponse) userInfoResponse;

        UserInfo userInfo;
        if (successInfoResponse.getUserInfoJWT() != null) {
            SignedJWT signedJWT = (SignedJWT) successInfoResponse.getUserInfoJWT();

            // TODO Support for encryption
            boolean valid = signedJWT.verify(new MACVerifier(configuration.getSSOIdTokenSecret()));  // TODO Configurable !!
            if (!valid) {
                ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-015", "JWT Signature Validation failed");
                throw new OctopusRetrievalException(errorObject);

            }

            userInfo = new UserInfo(signedJWT.getJWTClaimsSet());
        } else {
            userInfo = successInfoResponse.getUserInfo();
        }

        // We always use scope 'octopus' so JWT is always signed and according spec, we need iss, aud and added nonce ourself.
        List<String> claimsWithIssue = validateUserInfo(userInfo, variableClientData);

        if (!claimsWithIssue.isEmpty()) {
            StringBuilder claimsWithError = new StringBuilder();
            for (String claim : claimsWithIssue) {
                if (claimsWithError.length() > 0) {
                    claimsWithError.append(", ");
                }
                claimsWithError.append(claim);
            }
            ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-016", "JWT claim Validation failed : " + claimsWithError.toString());
            throw new OctopusRetrievalException(errorObject);

        }

        OctopusSSOUser user = octopusSSOUserConverter.fromUserInfo(userInfo, userInfoJSONProvider);

        user.setBearerAccessToken(accessToken);
        return user;
    }

    private List<String> validateUserInfo(UserInfo userInfo, OpenIdVariableClientData variableClientData) {
        List<String> result = new ArrayList<String>();

        if (variableClientData.getRootURL() != null) {
            if (!variableClientData.getNonce().equals(Nonce.parse(userInfo.getStringClaim("nonce")))) {
                result.add("nonce");
            }
        }

        if (!configuration.getOctopusSSOServer().equals(userInfo.getStringClaim("iss"))) {
            result.add("iss");
        }

        if (userInfo.getDateClaim("exp") == null || userInfo.getDateClaim("exp").before(new Date())) {
            result.add("exp");
        }

        if (variableClientData.getRootURL() != null) {
            if (!configuration.getSSOClientId().equals(userInfo.getStringClaim("aud"))) {
                result.add("aud");
            }
        }

        return result;

    }

}
