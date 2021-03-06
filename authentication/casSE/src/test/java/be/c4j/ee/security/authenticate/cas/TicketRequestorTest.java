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
package be.c4j.ee.security.authenticate.cas;

import be.c4j.ee.security.authentication.cas.CasSEConfiguration;
import be.c4j.ee.security.authentication.cas.TicketRequestor;
import be.c4j.ee.security.authentication.cas.exception.CasAuthenticationException;
import be.c4j.test.TestConfigSource;
import net.jadler.Jadler;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class TicketRequestorTest {

    private TicketRequestor requestor;

    @Before
    public void setup() {
        requestor = new TicketRequestor(new CasSEConfiguration());
    }

    @Before
    public void setUp() {
        Jadler.initJadler();
    }

    @After
    public void tearDown() {
        Jadler.closeJadler();
        ConfigResolver.freeConfigSources();
    }

    @Test
    public void getGrantingTicket() {
        configureParameters();
        Jadler.onRequest()
                .havingPathEqualTo("/cas/v1/tickets")
                .havingBody(new StringBaseMatcher("username=ictextern4&password=1mhe%261mka"))
                .respond()
                .withStatus(201)
                .withHeader("Location", "/cas/v1/tickets/TheAssignedTicket");


        UsernamePasswordToken token = new UsernamePasswordToken("ictextern4", "1mhe&1mka");
        String ticket = requestor.getGrantingTicket(token);
        assertThat(ticket).isEqualTo("TheAssignedTicket");
    }

    private void configureParameters() {
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.server", "http://localhost:" + Jadler.port() + "/cas");
        parameters.put("CAS.service", "http://some.server/fictive/cient/url");
        TestConfigSource.defineConfigValue(parameters);

    }

    @Test(expected = CasAuthenticationException.class)
    public void getGrantingTicket_WrongCredentials() {
        configureParameters();

        Jadler.onRequest()
                .havingPathEqualTo("/cas/v1/tickets")
                .respond()
                .withStatus(401);

        UsernamePasswordToken token = new UsernamePasswordToken("ictextern4", "1mhe1mka");
        requestor.getGrantingTicket(token);
    }

    @Test
    public void getServiceTicket() {
        configureParameters();

        Jadler.onRequest()
                .havingPathEqualTo("/cas/v1/tickets/TheGrantingTicket")
                .havingBody(new StringBaseMatcher("service=http%3A%2F%2Fsome.server%2Ffictive%2Fcient%2Furl"))
                .respond()
                .withStatus(200)
                .withBody("theServiceTicket");

        String serviceTicket = requestor.getServiceTicket("TheGrantingTicket");
        assertThat(serviceTicket).isEqualTo("theServiceTicket");

    }

    private class StringBaseMatcher extends BaseMatcher<String> {

        private String expected;

        private StringBaseMatcher(String expected) {
            this.expected = expected;
        }

        @Override
        public boolean matches(Object item) {
            return expected.equals(item.toString());
        }

        @Override
        public void describeTo(Description description) {

        }
    }

}