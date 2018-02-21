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
package be.c4j.ee.security.credentials.authentication.mp.filter;

import be.c4j.ee.security.credentials.authentication.mp.token.MPJWTToken;
import be.c4j.ee.security.credentials.authentication.mp.token.MPToken;
import be.c4j.ee.security.token.IncorrectDataToken;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class MPUserFilterTest {

    private static final String JTI = "jti";
    private static final String SUB = "sub";
    private static final String UPN = "upn";
    private static final String PREFERRED_USERNAME = "username";
    private static final String AUD = "aud";
    private static final String ISS = "iss";
    private static final List<String> GROUPS = Arrays.asList("group1", "group2");
    private static final String ADDITIONAL = "additional";

    @Mock
    private MPBearerTokenHandler tokenHandlerMock;

    @InjectMocks
    private MPUserFilter mpUserFilter;

    // Not really injedtec, but needed as method parameters
    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @Test
    public void createToken_handleExtremeMinimum() throws Exception {
        // Not really correct, but when custom MPBearerTokenHandler which should allow everything ...
        when(requestMock.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer <<mpToken>>");
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(new JWSAlgorithm("RS256")), new JWTClaimsSet.Builder().build());
        when(tokenHandlerMock.processToken("<<mpToken>>")).thenReturn(signedJWT);

        AuthenticationToken token = mpUserFilter.createToken(requestMock, responseMock);
        assertThat(token).isNotNull();
        assertThat(token).isInstanceOf(MPToken.class);
    }

    @Test
    public void createToken() throws Exception {
        // Not really correct, but when custom MPBearerTokenHandler which should allow everything ...
        when(requestMock.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer <<mpToken>>");
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(new JWSAlgorithm("RS256")), defineClaimSet());
        when(tokenHandlerMock.processToken("<<mpToken>>")).thenReturn(signedJWT);

        AuthenticationToken token = mpUserFilter.createToken(requestMock, responseMock);
        assertThat(token).isNotNull();
        assertThat(token).isInstanceOf(MPToken.class);

        MPToken mpToken = (MPToken) token;
        assertThat(mpToken.getId()).isEqualTo(JTI);

        MPJWTToken mpjwtToken = (MPJWTToken) mpToken.getCredentials();

        assertThat(mpjwtToken.getJti()).isEqualTo(JTI);
        assertThat(mpjwtToken.getSub()).isEqualTo(SUB);
        assertThat(mpjwtToken.getUpn()).isEqualTo(UPN);
        assertThat(mpjwtToken.getPreferredUsername()).isEqualTo(PREFERRED_USERNAME);
        assertThat(mpjwtToken.getAud()).containsOnly(AUD);
        assertThat(mpjwtToken.getIss()).isEqualTo(ISS);
        assertThat(mpjwtToken.getExp()).isNotNull();
        assertThat(mpjwtToken.getIat()).isNotNull();
        assertThat(mpjwtToken.getGroups()).containsOnly("group1", "group2");
        assertThat(mpjwtToken.getAdditionalClaims()).hasSize(1);
        assertThat(mpjwtToken.getAdditionalClaims()).containsOnlyKeys("additional");
        assertThat(mpjwtToken.getAdditionalClaims()).containsValues(ADDITIONAL);

    }

    @Test(expected = AuthenticationException.class)
    public void createToken_invalidByHandler() throws Exception {
        when(requestMock.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer <<mpToken>>");

        when(tokenHandlerMock.processToken("<<mpToken>>")).thenThrow(new AuthenticationException());

        mpUserFilter.createToken(requestMock, responseMock);

    }

    @Test
    public void createToken_missingToken() throws Exception {
        // Not really correct, but when custom MPBearerTokenHandler which should allow everything ...
        when(requestMock.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer ");

        AuthenticationToken token = mpUserFilter.createToken(requestMock, responseMock);
        assertThat(token).isNotNull();
        assertThat(token).isInstanceOf(IncorrectDataToken.class);

        verify(tokenHandlerMock, never()).processToken(anyString());

    }

    @Test
    public void createToken_missingBearer() throws Exception {
        // Not really correct, but when custom MPBearerTokenHandler which should allow everything ...
        when(requestMock.getHeader(AUTHORIZATION_HEADER)).thenReturn("<<mpToken>> ");

        AuthenticationToken token = mpUserFilter.createToken(requestMock, responseMock);
        assertThat(token).isNotNull();
        assertThat(token).isInstanceOf(IncorrectDataToken.class);

        verify(tokenHandlerMock, never()).processToken(anyString());

    }

    @Test
    public void createToken_missingHeader() throws Exception {
        // Not really correct, but when custom MPBearerTokenHandler which should allow everything ...
        when(requestMock.getHeader(AUTHORIZATION_HEADER)).thenReturn(null);

        AuthenticationToken token = mpUserFilter.createToken(requestMock, responseMock);
        assertThat(token).isNotNull();
        assertThat(token).isInstanceOf(IncorrectDataToken.class);

        verify(tokenHandlerMock, never()).processToken(anyString());

    }

    private JWTClaimsSet defineClaimSet() {
        return new JWTClaimsSet.Builder()
                .jwtID(JTI)
                .subject(SUB)
                .claim("upn", UPN)
                .claim("preferred_username", PREFERRED_USERNAME)
                .audience(AUD)
                .issuer(ISS)
                .expirationTime(new Date())
                .issueTime(new Date())
                .claim("groups", GROUPS)
                .claim("additional", ADDITIONAL)
                .build();
    }

}