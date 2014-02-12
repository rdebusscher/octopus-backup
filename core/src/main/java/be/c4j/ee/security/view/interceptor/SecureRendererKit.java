/*
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */

package be.c4j.ee.security.view.interceptor;

import javax.faces.render.RenderKit;
import javax.faces.render.RenderKitWrapper;
import javax.faces.render.Renderer;

/**
 * @author Rudy De Busscher
 */
public class SecureRendererKit extends RenderKitWrapper {
    private RenderKit renderKit;

    public SecureRendererKit(RenderKit renderKit) {
        this.renderKit = renderKit;
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
}
