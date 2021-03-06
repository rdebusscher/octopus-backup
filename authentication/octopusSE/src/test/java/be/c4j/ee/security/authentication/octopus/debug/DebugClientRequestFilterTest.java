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
package be.c4j.ee.security.authentication.octopus.debug;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import javax.ws.rs.client.ClientRequestContext;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class DebugClientRequestFilterTest {

    @Mock
    private ClientRequestContext clientRequestContextMock;

    private DebugClientRequestFilter filter;

    @Before
    public void setup() {
        filter = new DebugClientRequestFilter();
    }

    @After
    public void clearLoggers() {
        TestLoggerFactory.clear();
    }

    @Test
    public void filter() throws IOException, URISyntaxException {
        TestLogger logger = TestLoggerFactory.getTestLogger(DebugClientRequestFilter.class);

        URI uri = new URI("http://some.host/root");
        when(clientRequestContextMock.getUri()).thenReturn(uri);

        filter.filter(clientRequestContextMock);

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.INFO);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).endsWith(") Sending to http://some.host/root");

    }

    @Test
    public void filter_withEntity() throws IOException, URISyntaxException {
        TestLogger logger = TestLoggerFactory.getTestLogger(DebugClientRequestFilter.class);

        URI uri = new URI("http://some.host/root");
        when(clientRequestContextMock.getUri()).thenReturn(uri);
        when(clientRequestContextMock.getEntity()).thenReturn("The Entity Value");

        filter.filter(clientRequestContextMock);

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.INFO);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).endsWith(") Sending to http://some.host/root with entity 'The Entity Value'");

    }

    @Test
    public void filter_withAuthorization() throws IOException, URISyntaxException {
        TestLogger logger = TestLoggerFactory.getTestLogger(DebugClientRequestFilter.class);

        URI uri = new URI("http://some.host/root");
        when(clientRequestContextMock.getUri()).thenReturn(uri);
        when(clientRequestContextMock.getHeaderString(AUTHORIZATION_HEADER)).thenReturn("Authorization header");

        filter.filter(clientRequestContextMock);

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.INFO);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).endsWith(") Sending to http://some.host/root with Authorization header 'Authorization header'");

    }

    @Test
    public void filter_withAuthorizationAndEntity() throws IOException, URISyntaxException {
        TestLogger logger = TestLoggerFactory.getTestLogger(DebugClientRequestFilter.class);

        URI uri = new URI("http://some.host/root");
        when(clientRequestContextMock.getUri()).thenReturn(uri);
        when(clientRequestContextMock.getHeaderString(AUTHORIZATION_HEADER)).thenReturn("Authorization header");
        when(clientRequestContextMock.getEntity()).thenReturn("The Entity Value");

        filter.filter(clientRequestContextMock);

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.INFO);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).endsWith(") Sending to http://some.host/root with Authorization header 'Authorization header' and entity 'The Entity Value'");

    }

}