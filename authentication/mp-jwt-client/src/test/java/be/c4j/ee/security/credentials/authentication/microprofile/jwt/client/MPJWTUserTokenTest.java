/*
 * Copyright 2014-2018 Rudy De Busscher
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

import be.c4j.ee.security.credentials.authentication.jwt.client.JWTClaimsProvider;
import be.c4j.ee.security.credentials.authentication.microprofile.jwt.client.config.MPJWTClientConfig;
import be.c4j.ee.security.credentials.authentication.microprofile.jwt.client.exception.UserNameRequiredException;
import be.c4j.ee.security.credentials.authentication.microprofile.jwt.jwk.KeySelector;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.util.TimeUtil;
import be.c4j.test.util.ReflectionUtil;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_INFO;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class MPJWTUserTokenTest {

    private static final String KEY_ID = "keyId";
    private static final String USERNAME = "junit";

    private static RSAKey rsaKey;

    @Mock
    private UserPrincipal userPrincipalMock;

    @Mock
    private MPJWTClientConfig mpjwtClientConfigMock;

    @Mock
    private KeySelector keySelectorMock;

    @Mock
    private JWTClaimsProvider claimsProviderMock;

    @InjectMocks
    private MPJWTUserToken mpjwtUserToken;

    @BeforeClass
    public static void createKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        defineRSAKeyTest();

    }

    @Before
    public void setup() throws IllegalAccessException {
        ReflectionUtil.injectDependencies(mpjwtUserToken, new TimeUtil());

    }

    @Test
    public void createJWTUserToken_1() throws ParseException {
        // Basic scenario
        when(userPrincipalMock.getId()).thenReturn("LoggedIn");
        when(userPrincipalMock.getUserName()).thenReturn(USERNAME);

        AuthorizationInfo info = defineAuthorizationInfo();
        when(userPrincipalMock.getUserInfo(AUTHORIZATION_INFO)).thenReturn(info);

        when(keySelectorMock.selectSecretKey(null, null)).thenReturn(rsaKey);

        when(mpjwtClientConfigMock.getServerName()).thenReturn("serverName");  // No KeyId so we take server name
        when(mpjwtClientConfigMock.getJWTTimeToLive()).thenReturn(3);

        String userToken = mpjwtUserToken.createJWTUserToken(null, null, null);

        assertThat(userToken).isNotNull();
        SignedJWT signedJWT = SignedJWT.parse(userToken);
        validateHeader(signedJWT, "serverName");

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertThat(claimsSet.toJSONObject().keySet()).containsOnly("iss", "groups", "id", "exp", "iat", "jti", "sub", "preferred_username");

        assertThat(claimsSet.getIssuer()).isEqualTo("serverName");
        assertThat(claimsSet.getExpirationTime().getTime() - claimsSet.getIssueTime().getTime()).isEqualTo(3000);
        assertThat(claimsSet.getJWTID()).isNotNull(); // UUID so we can't test this thing
        assertThat(claimsSet.getSubject()).isEqualTo(USERNAME);
        assertThat(claimsSet.getStringClaim("preferred_username")).isEqualTo(USERNAME);

        assertThat(claimsSet.getStringListClaim("groups")).containsOnly("role1", "role2", "permission:2:*", "permission:1:*", "AppRole1", "AppRole2", "EXECUTE_TEST", "CHANGE_TEST");
    }

    @Test
    public void createJWTUserToken_2() throws ParseException {
        // Not authenticated user
        when(userPrincipalMock.getId()).thenReturn(null);

        String userToken = mpjwtUserToken.createJWTUserToken(null, null, null);

        assertThat(userToken).isNull();
    }

    @Test
    public void createJWTUserToken_3() throws ParseException {
        // keyId placed in header
        when(userPrincipalMock.getId()).thenReturn("LoggedIn");
        when(userPrincipalMock.getUserName()).thenReturn(USERNAME);

        AuthorizationInfo info = defineAuthorizationInfo();
        when(userPrincipalMock.getUserInfo(AUTHORIZATION_INFO)).thenReturn(info);

        when(keySelectorMock.selectSecretKey(KEY_ID, null)).thenReturn(rsaKey);

        when(mpjwtClientConfigMock.getServerName()).thenReturn("serverName");
        when(mpjwtClientConfigMock.getJWTTimeToLive()).thenReturn(3);

        String userToken = mpjwtUserToken.createJWTUserToken(KEY_ID, null, null);

        assertThat(userToken).isNotNull();
        SignedJWT signedJWT = SignedJWT.parse(userToken);
        validateHeader(signedJWT, KEY_ID);

    }

    @Test(expected = UserNameRequiredException.class)
    public void createJWTUserToken_4() throws ParseException {
        // userName is required (preferred_username/subject/upn fro spec
        when(userPrincipalMock.getId()).thenReturn("LoggedIn");

        mpjwtUserToken.createJWTUserToken(KEY_ID, null, null);

    }

    @Test
    public void createJWTUserToken_5() throws ParseException {
        // Additional claims
        when(userPrincipalMock.getId()).thenReturn("LoggedIn");
        when(userPrincipalMock.getUserName()).thenReturn(USERNAME);

        AuthorizationInfo info = defineAuthorizationInfo();
        when(userPrincipalMock.getUserInfo(AUTHORIZATION_INFO)).thenReturn(info);

        when(keySelectorMock.selectSecretKey(null, null)).thenReturn(rsaKey);

        when(mpjwtClientConfigMock.getServerName()).thenReturn("serverName");  // No KeyId so we take server name
        when(mpjwtClientConfigMock.getJWTTimeToLive()).thenReturn(3);

        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put("claim1", "valueClaim1");
        claims.put("claim2", "valueClaim2");
        when(claimsProviderMock.defineAdditionalClaims(userPrincipalMock)).thenReturn(claims);

        String userToken = mpjwtUserToken.createJWTUserToken(null, null, claimsProviderMock);

        assertThat(userToken).isNotNull();
        SignedJWT signedJWT = SignedJWT.parse(userToken);

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertThat(claimsSet.toJSONObject().keySet()).containsOnly("iss", "groups", "id", "exp", "iat", "jti", "sub", "preferred_username", "claim1", "claim2");

    }

    @Test
    public void createJWTUserToken_6() throws ParseException {
        // email -> upn
        when(userPrincipalMock.getId()).thenReturn("LoggedIn");
        when(userPrincipalMock.getUserName()).thenReturn(USERNAME);
        when(userPrincipalMock.getEmail()).thenReturn("jdoe@acme.com");

        AuthorizationInfo info = defineAuthorizationInfo();
        when(userPrincipalMock.getUserInfo(AUTHORIZATION_INFO)).thenReturn(info);

        when(keySelectorMock.selectSecretKey(null, null)).thenReturn(rsaKey);

        when(mpjwtClientConfigMock.getServerName()).thenReturn("serverName");  // No KeyId so we take server name
        when(mpjwtClientConfigMock.getJWTTimeToLive()).thenReturn(3);

        String userToken = mpjwtUserToken.createJWTUserToken(null, null, null);

        assertThat(userToken).isNotNull();
        SignedJWT signedJWT = SignedJWT.parse(userToken);

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertThat(claimsSet.toJSONObject().keySet()).containsOnly("iss", "groups", "id", "exp", "iat", "jti", "sub", "preferred_username", "upn");

    }


    private void validateHeader(SignedJWT signedJWT, String keyId) {
        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(new Algorithm("RS256"));
        assertThat(signedJWT.getHeader().getType()).isEqualTo(JOSEObjectType.JWT);
        assertThat(signedJWT.getHeader().getKeyID()).isEqualTo(keyId);
    }

    private AuthorizationInfo defineAuthorizationInfo() {
        SimpleAuthorizationInfo result = new SimpleAuthorizationInfo();

        result.addRole("role1");
        result.addRole("role2");

        result.addStringPermission("permission:1:*");
        result.addStringPermission("permission:2:*");

        result.addObjectPermission(new NamedDomainPermission("EXECUTE_TEST", "test:execute:*"));
        result.addObjectPermission(new NamedDomainPermission("CHANGE_TEST", "test:change:*"));

        result.addObjectPermission(new NamedApplicationRole("AppRole1"));
        result.addObjectPermission(new NamedApplicationRole("AppRole2"));

        result.addObjectPermission(new WildcardPermission("Wild:Card:*"));
        return result;
    }

    private static void defineRSAKeyTest() throws NoSuchAlgorithmException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair kp = generator.generateKeyPair();

        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

        rsaKey = new RSAKey.Builder(pub)
                .privateKey(priv)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(new Algorithm("PS512"))
                .keyID("JUnit")
                .build();
    }

}