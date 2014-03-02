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

package be.c4j.ee.security.view.component.user;

import be.c4j.ee.security.view.component.ComponentUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import javax.faces.component.UIComponent;
import javax.faces.view.facelets.ComponentConfig;
import javax.faces.view.facelets.ComponentHandler;
import javax.faces.view.facelets.FaceletContext;
import java.util.List;

/**
 * @author Rudy De Busscher
 */
public class RequiresUserHandler extends ComponentHandler {

    public RequiresUserHandler(ComponentConfig config) {
        super(config);
    }

    @Override
    public void onComponentPopulated(FaceletContext ctx, UIComponent component, UIComponent parent) {
        super.onComponentPopulated(ctx, component, parent);

        Boolean not = ComponentUtil.findValue(component, "not", Boolean.class);
        if (not == null) {
            not = Boolean.FALSE;
        }

        String target = ComponentUtil.findValue(component, "for", String.class);

        List<UIComponent> targets = ComponentUtil.findTargets(component, parent, target);

        Subject currentUser = SecurityUtils.getSubject();
        boolean isUser = currentUser.isAuthenticated();

        boolean notAllowed = !isUser;
        if (not) {
            notAllowed = !notAllowed;
        }

            if (notAllowed) {
                for (UIComponent targetComponent : targets) {
                    ComponentUtil.setNoAccess(targetComponent, null);
                }
            }
    }



}
