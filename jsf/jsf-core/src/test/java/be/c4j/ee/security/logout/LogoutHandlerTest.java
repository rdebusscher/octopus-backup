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
package be.c4j.ee.security.logout;

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.test.util.BeanManagerFake;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.faces.context.ExternalContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;


/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class LogoutHandlerTest {

    @Mock
    private ExternalContext externalContextMock;

    @Mock
    private OctopusJSFConfig octopusConfigMock;

    @InjectMocks
    private LogoutHandler logoutHandler;

    private BeanManagerFake beanManagerFake = new BeanManagerFake();

    @Mock
    private LogoutURLProcessor logoutURLProcessorMock;

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void getLogoutPage() {

        beanManagerFake.endRegistration();
        logoutHandler.init();

        when(externalContextMock.getRequestContextPath()).thenReturn("/demo");
        when(octopusConfigMock.getLogoutPage()).thenReturn("/");

        String logoutPage = logoutHandler.getLogoutPage(externalContextMock);

        assertThat(logoutPage).isEqualTo("/demo/");
    }

    @Test
    public void getLogoutPage_absolutePage() {
        beanManagerFake.endRegistration();
        logoutHandler.init();

        when(externalContextMock.getRequestContextPath()).thenReturn("/demo");
        String logoutPage = "http://domain.com/logout";
        when(octopusConfigMock.getLogoutPage()).thenReturn(logoutPage);

        String result = logoutHandler.getLogoutPage(externalContextMock);

        assertThat(result).isEqualTo(logoutPage);
    }

    @Test
    public void getLogoutPage_withProcessor() {
        beanManagerFake.registerBean(logoutURLProcessorMock, LogoutURLProcessor.class);
        beanManagerFake.endRegistration();
        logoutHandler.init();

        when(externalContextMock.getRequestContextPath()).thenReturn("/demo");
        String logoutPage = "http://domain.com/logout";
        when(octopusConfigMock.getLogoutPage()).thenReturn(logoutPage);

        String anotherPage = "http://domain.com/anotherPage";
        when(logoutURLProcessorMock.postProcessLogoutUrl(logoutPage)).thenReturn(anotherPage);

        String result = logoutHandler.getLogoutPage(externalContextMock);

        assertThat(result).isEqualTo(anotherPage);
    }
}