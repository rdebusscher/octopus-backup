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
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.faces.render.RenderKit;
import javax.faces.render.RenderKitWrapper;
import javax.faces.render.Renderer;

/**
 *
 */
public class SecureRendererKit extends RenderKitWrapper {
    private RenderKit renderKit;
    private boolean excludePrimeFacesMobile;

    public SecureRendererKit(RenderKit renderKit) {
        this.renderKit = renderKit;

        OctopusJSFConfig octopusConfig = BeanProvider.getContextualReference(OctopusJSFConfig.class);
        excludePrimeFacesMobile = Boolean.valueOf(octopusConfig.getExcludePrimeFacesMobile());
    }

    @Override
    public RenderKit getWrapped() {
        return renderKit;
    }

    @Override
    public Renderer getRenderer(String family, String rendererType) {
        if ("Dummy".equals(rendererType)) {
            return new DummyRenderer();
        }
        return super.getRenderer(family, rendererType);
    }

    @Override
    public void addRenderer(String s, String s2, Renderer renderer) {
        boolean addRenderer = true;
        if (excludePrimeFacesMobile && renderer.getClass().getName().contains("mobile")) {
            addRenderer = false;
        }
        if (addRenderer) {
            super.addRenderer(s, s2, renderer);
        }
    }
}
