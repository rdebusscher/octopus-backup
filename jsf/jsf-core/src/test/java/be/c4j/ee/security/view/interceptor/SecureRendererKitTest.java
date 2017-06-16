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
package be.c4j.ee.security.view.interceptor;

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.test.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.primefaces.component.commandbutton.CommandButtonRenderer;

import javax.faces.render.RenderKit;
import javax.faces.render.Renderer;

import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SecureRendererKitTest {

    @Mock
    private OctopusJSFConfig octopusJSFConfigMock;

    @Mock
    private RenderKit renderKitMock;

    private SecureRendererKit secureRendererKit;

    private BeanManagerFake beanManagerFake;


    @Before
    public void setup() throws IllegalAccessException {

        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(octopusJSFConfigMock, OctopusJSFConfig.class);

        beanManagerFake.endRegistration();

    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void addRenderer_NotExcludedBasicRenderer() throws IllegalAccessException {
        when(octopusJSFConfigMock.getExcludePrimeFacesMobile()).thenReturn("false");
        secureRendererKit = new SecureRendererKit(renderKitMock);

        Renderer renderer = new CommandButtonRenderer();
        secureRendererKit.addRenderer(null, null, renderer);

        verify(renderKitMock).addRenderer((String) isNull(), (String) isNull(), any(Renderer.class));
    }

    @Test
    public void addRenderer_NotExcludedMobileRenderer() throws IllegalAccessException {
        when(octopusJSFConfigMock.getExcludePrimeFacesMobile()).thenReturn("false");
        secureRendererKit = new SecureRendererKit(renderKitMock);

        Renderer renderer = new org.primefaces.mobile.renderkit.CommandButtonRenderer();
        secureRendererKit.addRenderer(null, null, renderer);

        verify(renderKitMock).addRenderer((String) isNull(), (String) isNull(), any(Renderer.class));
    }

    @Test
    public void addRenderer_ExcludedBasicRenderer() throws IllegalAccessException {
        when(octopusJSFConfigMock.getExcludePrimeFacesMobile()).thenReturn("true");
        secureRendererKit = new SecureRendererKit(renderKitMock);

        Renderer renderer = new CommandButtonRenderer();
        secureRendererKit.addRenderer(null, null, renderer);

        verify(renderKitMock).addRenderer((String) isNull(), (String) isNull(), any(Renderer.class));
    }

    @Test
    public void addRenderer_ExcludedMobileRenderer() throws IllegalAccessException {
        when(octopusJSFConfigMock.getExcludePrimeFacesMobile()).thenReturn("true");
        secureRendererKit = new SecureRendererKit(renderKitMock);

        Renderer renderer = new org.primefaces.mobile.renderkit.CommandButtonRenderer();
        secureRendererKit.addRenderer(null, null, renderer);

        verifyNoMoreInteractions(renderKitMock);
    }

}