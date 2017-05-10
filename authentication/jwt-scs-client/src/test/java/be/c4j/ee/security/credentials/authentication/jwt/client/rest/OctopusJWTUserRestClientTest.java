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
import be.c4j.ee.security.credentials.authentication.jwt.client.JWTUserToken;
import be.c4j.ee.security.credentials.authentication.jwt.client.rest.data.Data;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
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
public class OctopusJWTUserRestClientTest {

    private static final String AUTH_TOKEN = "AuthToken";

    @Mock
    private JWTUserToken jwtUserTokenMock;

    @Mock
    private ClientCustomization clientCustomizationMock;

    @InjectMocks
    private OctopusJWTUserRestClient client;

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

        client.init();
        Jadler.initJadler();
    }

    @After
    public void tearDown() {

        beanManagerFake.deregistration();
        Jadler.closeJadler();
    }

    @Test
    public void get() {
        when(jwtUserTokenMock.createJWTUserToken(null, null)).thenReturn(AUTH_TOKEN);

        Jadler.onRequest()
                .havingPathEqualTo("/endpoint")
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"field\":\"value\"}");
        Data data = client.get(defineEndpoint(), Data.class);
        assertThat(data.getField()).isEqualTo("value");

        Jadler.verifyThatRequest()
                .havingHeaderEqualTo("authorization", "Bearer " + AUTH_TOKEN)
                .havingHeaderEqualTo(ACCEPT, "application/json")
                .receivedOnce();
    }

    @Test(expected = OctopusUnauthorizedException.class)
    public void get_NotAuthenticated() {
        when(jwtUserTokenMock.createJWTUserToken(null, null)).thenReturn(AUTH_TOKEN);

        Jadler.onRequest()
                .havingPathEqualTo("/endpoint")
                .respond()
                .withStatus(401)
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"code\":\"ABC\", \"message\":\"DEF\"}");

        client.get(defineEndpoint(), Data.class);

    }

    private String defineEndpoint() {
        return String.format("http://localhost:%s/endpoint", Jadler.port());
    }

}