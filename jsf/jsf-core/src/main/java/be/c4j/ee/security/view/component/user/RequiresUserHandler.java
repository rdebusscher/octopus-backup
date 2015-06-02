/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.view.component.user;

import be.c4j.ee.security.view.component.ComponentUtil;
import be.c4j.ee.security.view.component.OctopusComponentHandler;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import javax.faces.component.UIComponent;
import javax.faces.view.facelets.ComponentConfig;
import java.util.List;

/**
 *
 */
public class RequiresUserHandler extends OctopusComponentHandler {

    public RequiresUserHandler(ComponentConfig config) {
        super(config);
    }

    @Override
    protected void handleComponentSecurity(UIComponent component, UIComponent parent) {
        Boolean not = ComponentUtil.findValue(component, "not", Boolean.class);
        if (not == null) {
            not = Boolean.FALSE;
        }

        String target = ComponentUtil.findValue(component, "for", String.class);

        List<UIComponent> targets = ComponentUtil.findTargets(component, parent, target);

        Subject currentUser = SecurityUtils.getSubject();
        boolean isUser = currentUser.isAuthenticated();

        // Remembered property, see issue #53
        if (!isUser) {
            Boolean remembered = ComponentUtil.findValue(component, "remembered", Boolean.class);
            if (remembered == null) {
                remembered = Boolean.FALSE;
            }
            if (remembered && currentUser.isRemembered()) {
                isUser = true;
            }
        }

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
