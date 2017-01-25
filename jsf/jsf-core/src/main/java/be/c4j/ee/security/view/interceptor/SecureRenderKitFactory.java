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

import javax.faces.context.FacesContext;
import javax.faces.render.RenderKit;
import javax.faces.render.RenderKitFactory;
import java.util.Iterator;

/**
 *
 */
public class SecureRenderKitFactory extends RenderKitFactory {

    private RenderKitFactory wrapped;

    public SecureRenderKitFactory(RenderKitFactory wrapped) {
        this.wrapped = wrapped;
    }

    @Override
    public void addRenderKit(String renderKitId, RenderKit renderKit) {
        wrapped.addRenderKit(renderKitId, renderKit);
    }

    @Override
    public RenderKit getRenderKit(FacesContext context, String renderKitId) {
        return new SecureRendererKit(wrapped.getRenderKit(context, renderKitId));
    }

    @Override
    public Iterator<String> getRenderKitIds() {
        return wrapped.getRenderKitIds();
    }
}
