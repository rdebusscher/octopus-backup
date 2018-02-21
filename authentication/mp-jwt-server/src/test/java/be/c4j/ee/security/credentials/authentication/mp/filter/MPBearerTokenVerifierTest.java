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

import be.c4j.ee.security.credentials.authentication.mp.config.MPConfiguration;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.test.util.ReflectionUtil;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.slf4j.Logger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class MPBearerTokenVerifierTest {

    private static final String AUDIENCE = "aud";

    @Mock
    private MPConfiguration mpConfigurationMock;

    @InjectMocks
    private MPBearerTokenVerifier mpBearerTokenVerifier;

    private Logger logger;

    @Before
    public void setup() throws IllegalAccessException {
        logger = TestLoggerFactory.getTestLogger(MPBearerTokenVerifier.class);
        ReflectionUtil.injectDependencies(mpBearerTokenVerifier, logger);
    }

    @After
    public void clearLoggers() {
        TestLoggerFactory.clear();

    }

    @Test
    public void init() {
        when(mpConfigurationMock.getAudience()).thenReturn(AUDIENCE);
        mpBearerTokenVerifier.init();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void init_missingAud() {
        mpBearerTokenVerifier.init();
    }

    @Test
    public void verify_header() {
        assertThat(mpBearerTokenVerifier.verify(createHeader(HEADER_CONTENT.CORRECT_ALGORITHM, HEADER_CONTENT.CORRECT_TYPE))).isTrue();
    }

    @Test
    public void verify_header_wrongAlgo() {
        assertThat(mpBearerTokenVerifier.verify(createHeader(HEADER_CONTENT.WRONG_ALGORITHM, HEADER_CONTENT.CORRECT_TYPE))).isFalse();
    }

    @Test
    public void verify_header_wrongType() {
        assertThat(mpBearerTokenVerifier.verify(createHeader(HEADER_CONTENT.CORRECT_ALGORITHM, HEADER_CONTENT.WRONG_TYPE))).isFalse();
    }

    @Test
    public void verify_header_wrongAlgoAndType() {
        assertThat(mpBearerTokenVerifier.verify(createHeader(HEADER_CONTENT.WRONG_ALGORITHM, HEADER_CONTENT.WRONG_TYPE))).isFalse();
    }

    @Test
    public void verify_claimSet() {
        when(mpConfigurationMock.getAudience()).thenReturn(AUDIENCE);
        assertThat(mpBearerTokenVerifier.verify(createClaims(CLAIM_CONTENT.CORRECT_AUDIENCE, CLAIM_CONTENT.CORRECT_DATE))).isTrue();
    }

    @Test
    public void verify_wrongAudience() {
        when(mpConfigurationMock.getAudience()).thenReturn(AUDIENCE);
        assertThat(mpBearerTokenVerifier.verify(createClaims(CLAIM_CONTENT.WRONG_AUDIENCE, CLAIM_CONTENT.CORRECT_DATE))).isFalse();
    }

    @Test
    public void verify_wrongDate() {
        when(mpConfigurationMock.getAudience()).thenReturn(AUDIENCE);
        assertThat(mpBearerTokenVerifier.verify(createClaims(CLAIM_CONTENT.CORRECT_AUDIENCE, CLAIM_CONTENT.WRONG_DATE))).isFalse();
    }

    @Test
    public void verify_wrongAudienceAndDate() {
        when(mpConfigurationMock.getAudience()).thenReturn(AUDIENCE);
        assertThat(mpBearerTokenVerifier.verify(createClaims(CLAIM_CONTENT.WRONG_AUDIENCE, CLAIM_CONTENT.WRONG_DATE))).isFalse();
    }

    private JWTClaimsSet createClaims(CLAIM_CONTENT... claimContent) {
        List<CLAIM_CONTENT> content = Arrays.asList(claimContent);
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        if (content.contains(CLAIM_CONTENT.WRONG_AUDIENCE)) {
            builder.audience("SomeAudience");
        }
        if (content.contains(CLAIM_CONTENT.CORRECT_AUDIENCE)) {
            builder.audience(AUDIENCE);
        }
        if (content.contains(CLAIM_CONTENT.WRONG_DATE)) {
            builder.expirationTime(createDate(-2));
        }
        if (content.contains(CLAIM_CONTENT.CORRECT_DATE)) {
            builder.expirationTime(createDate(2));
        }
        return builder.build();
    }

    private Date createDate(int addSeconds) {
        return new Date(System.currentTimeMillis() + addSeconds * 1000);
    }

    private JWSHeader createHeader(HEADER_CONTENT... headerContent) {
        List<HEADER_CONTENT> content = Arrays.asList(headerContent);
        JWSHeader.Builder builder = null;
        if (content.contains(HEADER_CONTENT.CORRECT_ALGORITHM)) {
            builder = new JWSHeader.Builder(JWSAlgorithm.RS256);
        }
        if (content.contains(HEADER_CONTENT.WRONG_ALGORITHM)) {
            builder = new JWSHeader.Builder(JWSAlgorithm.RS512);
        }
        if (content.contains(HEADER_CONTENT.CORRECT_TYPE)) {
            builder.type(JOSEObjectType.JWT);
        }
        if (content.contains(HEADER_CONTENT.WRONG_TYPE)) {
            builder.type(JOSEObjectType.JOSE);
        }
        return builder.build();
    }

    private static enum CLAIM_CONTENT {
        WRONG_AUDIENCE, CORRECT_AUDIENCE, WRONG_DATE, CORRECT_DATE;
    }

    private static enum HEADER_CONTENT {
        WRONG_ALGORITHM, CORRECT_ALGORITHM, WRONG_TYPE, CORRECT_TYPE;
    }

}