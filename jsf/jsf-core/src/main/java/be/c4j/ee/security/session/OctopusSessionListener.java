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
package be.c4j.ee.security.session;

import org.apache.deltaspike.core.api.provider.BeanManagerProvider;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 *
 */

public class OctopusSessionListener implements HttpSessionListener {
    @Override
    public void sessionCreated(HttpSessionEvent se) {
        BeanManagerProvider.getInstance().getBeanManager().fireEvent(new ApplicationUsageEvent(se.getSession(), UserAction.FIRST_ACCESS));
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {
        BeanManagerProvider.getInstance().getBeanManager().fireEvent(new ApplicationUsageEvent(se.getSession(), UserAction.SESSION_END));
    }


}
