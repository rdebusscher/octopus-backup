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
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientResponseContext;
import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class DebugClientResponseFilterTest {

    @Mock
    private ClientRequestContext clientRequestContextMock;

    @Mock
    private ClientResponseContext clientResponseContextMock;

    @Mock
    private InputStream inputStreamMock;

    private DebugClientResponseFilter filter;

    @Before
    public void setup() {
        filter = new DebugClientResponseFilter();
    }

    @After
    public void clearLoggers() {
        TestLoggerFactory.clear();
    }

    @Test
    public void filter() throws IOException {
        TestLogger logger = TestLoggerFactory.getTestLogger(DebugClientResponseFilter.class);

        when(clientResponseContextMock.getStatus()).thenReturn(201);

        filter.filter(clientRequestContextMock, clientResponseContextMock);

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.INFO);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).endsWith(") Received response with status 201");

    }

    @Test
    public void filter_withEntity() throws IOException {
        TestLogger logger = TestLoggerFactory.getTestLogger(DebugClientResponseFilter.class);

        when(clientResponseContextMock.getStatus()).thenReturn(200);
        when(clientResponseContextMock.hasEntity()).thenReturn(true);
        when(clientResponseContextMock.getEntityStream()).thenReturn(inputStreamMock);
        when(clientRequestContextMock.getProperty(CorrelationCounter.class.getName())).thenReturn(12);

        when(inputStreamMock.read(any(byte[].class), anyInt(), anyInt())).thenAnswer(new Answer<Integer>() {
            @Override
            public Integer answer(InvocationOnMock invocation) throws Throwable {
                String entityValue = "The entity value from the stream";

                byte[] data = (byte[]) invocation.getArguments()[0];
                for (int i = 0; i < entityValue.length(); i++) {
                    data[i] = (byte) entityValue.charAt(i);
                }

                return entityValue.length();
            }
        });
        filter.filter(clientRequestContextMock, clientResponseContextMock);

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.INFO);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).endsWith(") Received response with status 200 and content 'The entity value from the stream'");

    }

}