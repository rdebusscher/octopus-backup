/*
 * Copyright 2014-2018 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.session;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.twostep.TwoStepSubject;
import org.apache.shiro.SecurityUtils;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class SessionUtil {

    @Inject
    private OctopusConfig octopusConfig;

    public void invalidateCurrentSession(HttpServletRequest request) {
        if (!octopusConfig.getIsSessionInvalidatedAtLogin()) {
            // Defined with config that developer don't was logout/session invalidation.
            return;
        }

        if (SecurityUtils.getSubject() instanceof TwoStepSubject) {
            // Otherwise the principals are cleared from the current subject which isn't something we want :)
            return;
        }
        HttpSession session = request.getSession();

        HashMap<String, Object> content = new HashMap<String, Object>();
        Enumeration keys = session.getAttributeNames();

        while (keys.hasMoreElements()) {
            String key = (String) keys.nextElement();
            content.put(key, session.getAttribute(key));
            session.removeAttribute(key);
        }

        SecurityUtils.getSubject().logout();

        session = request.getSession(true);
        for (Map.Entry m : content.entrySet()) {
            //  m.getValue() comes from session so we assume it is Serializable the first time.
            session.setAttribute((String) m.getKey(), m.getValue());
        }
        content.clear();
    }

}
