/*
 * Copyright 2014-2018 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.sso.server.filter;

import be.c4j.ee.security.shiro.OctopusUserFilter;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.cookie.SSOHelper;
import be.c4j.test.util.BeanManagerFake;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OIDCEndpointFilterTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private ClientInfoRetriever clientInfoRetrieverMock;

    @Mock
    private SSOHelper ssoHelperMock;

    @Mock
    private Subject subjectMock;

    @Mock
    private PrintWriter printWriterMock;

    @Mock
    private OctopusClientCredentialsSelector clientCredentialsSelectorMock;

    @Captor
    private ArgumentCaptor<AuthenticationRequest> authenticationRequestCapture;

    @Captor
    private ArgumentCaptor<String> stringCapture;

    @InjectMocks
    private OIDCEndpointFilter endpointFilter;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {

        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(clientInfoRetrieverMock, ClientInfoRetriever.class);
        beanManagerFake.registerBean(ssoHelperMock, SSOHelper.class);
        beanManagerFake.registerBean(clientCredentialsSelectorMock, OctopusClientCredentialsSelector.class);

        beanManagerFake.endRegistration();

        endpointFilter.init();
        endpointFilter.setUserFilter(new OctopusUserFilter());
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void onPreHandle_authenticate_happyCase() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        when(httpServletRequestMock.getContextPath()).thenReturn("/oidc");
        ThreadContext.bind(subjectMock);
        when(subjectMock.getPrincipal()).thenReturn(new Object());  // Anything will do as principal

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2");
        when(clientInfoRetrieverMock.retrieveInfo("demo-clientId")).thenReturn(clientInfo);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, null, null);
        assertThat(data).isEqualTo(true);

        verify(httpServletRequestMock).setAttribute(stringCapture.capture(), authenticationRequestCapture.capture());

        assertThat(stringCapture.getValue()).isEqualTo(AbstractRequest.class.getName());
        assertThat(authenticationRequestCapture.getValue()).isInstanceOf(AuthenticationRequest.class);

        verify(ssoHelperMock).markAsSSOLogin(httpServletRequestMock, "demo-clientId");
    }

    @Test
    public void onPreHandle_authenticate_MissingClientId() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("http://localhost:8080/sso-app2/octopus/sso/SSOCallback?error_description=Invalid+request%3A+Missing+%22client_id%22+parameter&state=stateCode&error=invalid_request");
        verifyNoMoreInteractions(ssoHelperMock);

    }

    @Test
    public void onPreHandle_authenticate_MissingClientId_NoValidRedirect() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&redirect_uri=sso-app2&scope=openid&state=stateCode&nonce=nonceCode");

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("sso-app2?error_description=Invalid+request%3A+Missing+%22client_id%22+parameter&state=stateCode&error=invalid_request");
        verifyNoMoreInteractions(ssoHelperMock);

    }

    @Test
    public void onPreHandle_authenticate_MissingRedirectURI() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&scope=openid&state=stateCode&nonce=nonceCode");

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(printWriterMock).println(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("Invalid request: Missing \"redirect_uri\" parameter");
    }

    @Test
    public void onPreHandle_authenticate_unknownClientId() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        when(clientInfoRetrieverMock.retrieveInfo("demo-clientId")).thenReturn(null);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("http://localhost:8080/sso-app2/octopus/sso/SSOCallback?error_description=Client+authentication+failed%3A+Unknown+%22client_id%22+parameter+value&state=stateCode&error=invalid_client");

        verify(httpServletRequestMock, never()).setAttribute(stringCapture.capture(), authenticationRequestCapture.capture());
        verifyNoMoreInteractions(ssoHelperMock);
    }

    @Test
    public void onPreHandle_authenticate_unknownRedirectURI() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app1");
        when(clientInfoRetrieverMock.retrieveInfo("demo-clientId")).thenReturn(clientInfo);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("http://localhost:8080/sso-app2/octopus/sso/SSOCallback?error_description=Client+authentication+failed%3A+Unknown+%22redirect_uri%22+parameter+value&state=stateCode&error=invalid_client");

        verify(httpServletRequestMock, never()).setAttribute(stringCapture.capture(), authenticationRequestCapture.capture());
        verifyNoMoreInteractions(ssoHelperMock);
    }

    @Test
    public void onPreHandle_token_happyCase() throws Exception {

        StringBuffer url = new StringBuffer();
        url.append("http://some.server/oidc/octopus/sso/token");
        when(httpServletRequestMock.getRequestURL()).thenReturn(url);
        when(httpServletRequestMock.getMethod()).thenReturn("POST");
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/token");

        String secretString = generateSecret();

        String jwtData = generateJWT("junit_client_id", secretString, new URI("http://some.server/oidc/octopus/sso/token"));
        String body = jwtData + "&code=81np_6iMIkw52117lb_YF71seITMdzOGqmyC02se3jY&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback";

        // Read the info from the client
        BufferedReader readerMock = Mockito.mock(BufferedReader.class);
        when(readerMock.readLine()).thenReturn(body);
        when(httpServletRequestMock.getReader()).thenReturn(readerMock);

        // To make the rest of the code happy
        when(httpServletRequestMock.getContextPath()).thenReturn("/oidc");
        ThreadContext.bind(subjectMock);
        when(subjectMock.getPrincipal()).thenReturn(new Object());  // Anything will do as principal

        // Client JWT validation
        List<Secret> secrets = new ArrayList<Secret>();
        secrets.add(new Secret(secretString));
        when(clientCredentialsSelectorMock.selectClientSecrets(new ClientID("junit_client_id"), ClientAuthenticationMethod.CLIENT_SECRET_JWT, null)).thenReturn(secrets);

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2");
        when(clientInfoRetrieverMock.retrieveInfo("junit_client_id")).thenReturn(clientInfo);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, null, null);
        assertThat(data).isEqualTo(true);

        verify(httpServletRequestMock, times(2)).setAttribute(anyString(), ArgumentMatchers.any());

        // client_assertion=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZW1vLWNsaWVudElkIiwiYXVkIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL3NlY3VyaXR5XC9vY3RvcHVzXC9zc29cL3Rva2VuIiwiaXNzIjoiZGVtby1jbGllbnRJZCIsImV4cCI6MTQ4OTQ5NzY5NywianRpIjoiOWJXQmRlU3pNdnhCbDJiTmpkc1lrN2NiN2VqU092ZDJWVnpqS2VETFNZcyJ9.2pPH6hqARMyRDpW7kn00qVgeN7y0UF0iDgNeyX-1gkshDJBCKmt7NcqgRPTLUh05VY7az0N98cRS608KzfJ2oQ&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer

        // client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=81np_6iMIkw52117lb_YF71seITMdzOGqmyC02se3jY&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZW1vLWNsaWVudElkIiwiYXVkIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL3NlY3VyaXR5XC9vY3RvcHVzXC9zc29cL3Rva2VuIiwiaXNzIjoiZGVtby1jbGllbnRJZCIsImV4cCI6MTQ4OTQ5NzY5NywianRpIjoiOWJXQmRlU3pNdnhCbDJiTmpkc1lrN2NiN2VqU092ZDJWVnpqS2VETFNZcyJ9.2pPH6hqARMyRDpW7kn00qVgeN7y0UF0iDgNeyX-1gkshDJBCKmt7NcqgRPTLUh05VY7az0N98cRS608KzfJ2oQ
    }

    @Test
    public void onPreHandle_token_happyCase_fromAdditional() throws Exception {

        StringBuffer url = new StringBuffer();
        url.append("http://some.server/oidc/octopus/sso/token");
        when(httpServletRequestMock.getRequestURL()).thenReturn(url);
        when(httpServletRequestMock.getMethod()).thenReturn("POST");
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/token");

        String secretString = generateSecret();

        String jwtData = generateJWT("junit_client_id", secretString, new URI("http://some.server/oidc/octopus/sso/token"));
        String body = jwtData + "&code=81np_6iMIkw52117lb_YF71seITMdzOGqmyC02se3jY&grant_type=authorization_code&redirect_uri=http%3A%2F%2Falias%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback";

        // Read the info from the client
        BufferedReader readerMock = Mockito.mock(BufferedReader.class);
        when(readerMock.readLine()).thenReturn(body);
        when(httpServletRequestMock.getReader()).thenReturn(readerMock);

        // To make the rest of the code happy
        when(httpServletRequestMock.getContextPath()).thenReturn("/oidc");
        ThreadContext.bind(subjectMock);
        when(subjectMock.getPrincipal()).thenReturn(new Object());  // Anything will do as principal

        // Client JWT validation
        List<Secret> secrets = new ArrayList<Secret>();
        secrets.add(new Secret(secretString));
        when(clientCredentialsSelectorMock.selectClientSecrets(new ClientID("junit_client_id"), ClientAuthenticationMethod.CLIENT_SECRET_JWT, null)).thenReturn(secrets);

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2");
        clientInfo.additionalCallbackURL("http://alias/sso-app2");
        when(clientInfoRetrieverMock.retrieveInfo("junit_client_id")).thenReturn(clientInfo);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, null, null);
        assertThat(data).isEqualTo(true);

        verify(httpServletRequestMock, times(2)).setAttribute(anyString(), ArgumentMatchers.any());

        // client_assertion=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZW1vLWNsaWVudElkIiwiYXVkIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL3NlY3VyaXR5XC9vY3RvcHVzXC9zc29cL3Rva2VuIiwiaXNzIjoiZGVtby1jbGllbnRJZCIsImV4cCI6MTQ4OTQ5NzY5NywianRpIjoiOWJXQmRlU3pNdnhCbDJiTmpkc1lrN2NiN2VqU092ZDJWVnpqS2VETFNZcyJ9.2pPH6hqARMyRDpW7kn00qVgeN7y0UF0iDgNeyX-1gkshDJBCKmt7NcqgRPTLUh05VY7az0N98cRS608KzfJ2oQ&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer

        // client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=81np_6iMIkw52117lb_YF71seITMdzOGqmyC02se3jY&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZW1vLWNsaWVudElkIiwiYXVkIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL3NlY3VyaXR5XC9vY3RvcHVzXC9zc29cL3Rva2VuIiwiaXNzIjoiZGVtby1jbGllbnRJZCIsImV4cCI6MTQ4OTQ5NzY5NywianRpIjoiOWJXQmRlU3pNdnhCbDJiTmpkc1lrN2NiN2VqU092ZDJWVnpqS2VETFNZcyJ9.2pPH6hqARMyRDpW7kn00qVgeN7y0UF0iDgNeyX-1gkshDJBCKmt7NcqgRPTLUh05VY7az0N98cRS608KzfJ2oQ
    }

    private String generateSecret() {
        byte[] secret = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(secret);
        return Base64.encode(secret).toString();
    }

    private String generateJWT(String ssoClientId, String ssoClientSecret, URI tokenEndPoint) {
        HTTPRequest httpRequest = null;
        try {
            httpRequest = new HTTPRequest(HTTPRequest.Method.valueOf("POST"), new URL("http://some.server/oidc"));
            ClientAuthentication clientAuth = new ClientSecretJWT(new ClientID(ssoClientId)
                    , tokenEndPoint, JWSAlgorithm.HS256, new Secret(ssoClientSecret));  // TODO Is the String usage correct?

            httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
            clientAuth.applyTo(httpRequest);

        } catch (JOSEException e) {
            fail(e.getMessage());
        } catch (MalformedURLException e) {
            fail(e.getMessage());
        }
        return httpRequest.getQuery();
    }

    @Test
    public void onPreHandle_token_NoClientAuth() throws Exception {

        StringBuffer url = new StringBuffer();
        url.append("http://some.server/oidc/octopus/sso/token");
        when(httpServletRequestMock.getRequestURL()).thenReturn(url);
        when(httpServletRequestMock.getMethod()).thenReturn("POST");
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/token");

        BufferedReader readerMock = Mockito.mock(BufferedReader.class);
        when(readerMock.readLine()).thenReturn("code=81np_6iMIkw52117lb_YF71seITMdzOGqmyC02se3jY&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback");
        when(httpServletRequestMock.getReader()).thenReturn(readerMock);

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verify(printWriterMock).println(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("{\"error_description\":\"Invalid request: Missing required \\\"client_id\\\" parameter\",\"error\":\"invalid_request\"}");

        verify(httpServletRequestMock, never()).setAttribute(anyString(), ArgumentMatchers.any());
    }

    @Test
    public void onPreHandle_token_MissingAuthorizationCode() throws Exception {

        StringBuffer url = new StringBuffer();
        url.append("http://some.server/oidc/octopus/sso/token");
        when(httpServletRequestMock.getRequestURL()).thenReturn(url);
        when(httpServletRequestMock.getMethod()).thenReturn("POST");
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/token");

        BufferedReader readerMock = Mockito.mock(BufferedReader.class);
        when(readerMock.readLine()).thenReturn("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZW1vLWNsaWVudElkIiwiYXVkIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL3NlY3VyaXR5XC9vY3RvcHVzXC9zc29cL3Rva2VuIiwiaXNzIjoiZGVtby1jbGllbnRJZCIsImV4cCI6MTQ4OTQ5NzY5NywianRpIjoiOWJXQmRlU3pNdnhCbDJiTmpkc1lrN2NiN2VqU092ZDJWVnpqS2VETFNZcyJ9.2pPH6hqARMyRDpW7kn00qVgeN7y0UF0iDgNeyX-1gkshDJBCKmt7NcqgRPTLUh05VY7az0N98cRS608KzfJ2oQ");
        when(httpServletRequestMock.getReader()).thenReturn(readerMock);

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock, null);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verify(printWriterMock).println(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("{\"error_description\":\"Invalid request: Missing or empty \\\"code\\\" parameter\",\"error\":\"invalid_request\"}");

        verify(httpServletRequestMock, never()).setAttribute(anyString(), ArgumentMatchers.any());

    }

}