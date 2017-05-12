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
package be.c4j.ee.security.credentials.authentication.jwt.client.rest;

import be.c4j.ee.security.authentication.octopus.client.ClientCustomization;
import be.c4j.ee.security.credentials.authentication.jwt.client.JWTSystemToken;
import be.c4j.ee.security.credentials.authentication.jwt.client.rest.data.Data;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.jwt.config.MappingSystemAccountToApiKey;
import be.c4j.test.util.BeanManagerFake;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import net.jadler.Jadler;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.ws.rs.client.Client;

import static javax.ws.rs.core.HttpHeaders.ACCEPT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

/**
 *
 */

@RunWith(MockitoJUnitRunner.class)
public class OctopusSCSSystemRestClientTest {

    private static final String AUTH_TOKEN = "AuthToken";
    private static final String X_API_TOKEN = "apiKey";
    private static final String SYSTEM_ACCOUNT = "systemAccount";

    @Mock
    private JWTSystemToken jwtSystemTokenMock;

    @Mock
    private ClientCustomization clientCustomizationMock;

    @Mock
    private MappingSystemAccountToApiKey mappingSystemAccountToApiKeyMock;

    @InjectMocks
    private OctopusSCSSystemRestClient client;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(clientCustomizationMock, ClientCustomization.class);
        beanManagerFake.endRegistration();

        doAnswer(new Answer<Void>() {
            @Override
            public Void answer(InvocationOnMock invocation) throws Throwable {
                Client client = invocation.getArgument(0);
                client.register(JacksonFeature.class);
                return null;
            }
        }).when(clientCustomizationMock).customize(any(Client.class), any(Class.class));

        Jadler.initJadler();
    }

    @After
    public void tearDown() {

        beanManagerFake.deregistration();
        Jadler.closeJadler();
    }

    @Test
    public void get() {
        when(mappingSystemAccountToApiKeyMock.containsOnlyOneMapping()).thenReturn(true);
        when(mappingSystemAccountToApiKeyMock.getOnlyAccount()).thenReturn(SYSTEM_ACCOUNT);
        when(mappingSystemAccountToApiKeyMock.getApiKey(SYSTEM_ACCOUNT)).thenReturn(X_API_TOKEN);
        when(jwtSystemTokenMock.createJWTSystemToken(SYSTEM_ACCOUNT)).thenReturn(AUTH_TOKEN);

        client.init();

        Jadler.onRequest()
                .havingPathEqualTo("/endpoint")
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"field\":\"value\"}");
        Data data = client.get(defineEndpoint(), Data.class);
        assertThat(data.getField()).isEqualTo("value");

        Jadler.verifyThatRequest()
                .havingHeaderEqualTo("authorization", "Bearer " + AUTH_TOKEN)
                .havingHeaderEqualTo("x-api-key", X_API_TOKEN)
                .havingHeaderEqualTo(ACCEPT, "application/json")
                .receivedOnce();
    }

    @Test(expected = OctopusUnauthorizedException.class)
    public void get_NotAuthenticated() {
        when(mappingSystemAccountToApiKeyMock.containsOnlyOneMapping()).thenReturn(true);
        when(mappingSystemAccountToApiKeyMock.getOnlyAccount()).thenReturn(SYSTEM_ACCOUNT);
        when(mappingSystemAccountToApiKeyMock.getApiKey(SYSTEM_ACCOUNT)).thenReturn(X_API_TOKEN);
        when(jwtSystemTokenMock.createJWTSystemToken(SYSTEM_ACCOUNT)).thenReturn(AUTH_TOKEN);

        client.init();

        Jadler.onRequest()
                .havingPathEqualTo("/endpoint")
                .respond()
                .withStatus(401)
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"code\":\"ABC\", \"message\":\"DEF\"}");

        client.get(defineEndpoint(), Data.class);

    }

    @Test(expected = OctopusConfigurationException.class)
    public void get_AccountNotFound() {
        when(mappingSystemAccountToApiKeyMock.containsOnlyOneMapping()).thenReturn(true);
        when(mappingSystemAccountToApiKeyMock.getOnlyAccount()).thenReturn(SYSTEM_ACCOUNT);
        when(jwtSystemTokenMock.createJWTSystemToken(SYSTEM_ACCOUNT)).thenThrow(new OctopusConfigurationException("Account not found"));

        client.init();

        try {
            client.get(defineEndpoint(), Data.class);
        } finally {
            Jadler.verifyThatRequest()
                    .receivedNever();
        }
    }


    @Test
    public void get_WithParameters() {
        when(mappingSystemAccountToApiKeyMock.containsOnlyOneMapping()).thenReturn(true);
        when(mappingSystemAccountToApiKeyMock.getOnlyAccount()).thenReturn(SYSTEM_ACCOUNT);
        when(mappingSystemAccountToApiKeyMock.getApiKey(SYSTEM_ACCOUNT)).thenReturn(X_API_TOKEN);
        when(jwtSystemTokenMock.createJWTSystemToken(SYSTEM_ACCOUNT)).thenReturn(AUTH_TOKEN);

        client.init();

        Jadler.onRequest()
                .havingPathEqualTo("/endpoint")
                .havingParameterEqualTo("name1", "value1")
                .havingParameterEqualTo("name2", "value2")
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"field\":\"value\"}");

        URLArgument argument1 = new URLArgument("name1", "value1");
        URLArgument argument2 = new URLArgument("name2", "value2");
        Data data = client.get(defineEndpoint(), Data.class, argument1, argument2);
        assertThat(data.getField()).isEqualTo("value");

        Jadler.verifyThatRequest()
                .havingHeaderEqualTo("authorization", "Bearer " + AUTH_TOKEN)
                .havingHeaderEqualTo("x-api-key", X_API_TOKEN)
                .havingHeaderEqualTo(ACCEPT, "application/json")
                .receivedOnce();
    }

    private String defineEndpoint() {
        return String.format("http://localhost:%s/endpoint", Jadler.port());
    }
}