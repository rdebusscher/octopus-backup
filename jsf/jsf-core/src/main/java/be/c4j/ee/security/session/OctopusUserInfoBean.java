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

import be.c4j.ee.security.filter.SessionHijackingFilter;

import javax.enterprise.context.SessionScoped;
import javax.faces.context.FacesContext;
import javax.inject.Named;
import java.io.Serializable;

/**
 *
 */
@SessionScoped
@Named
public class OctopusUserInfoBean implements Serializable {

    // We can't inject HttpSession as it is not supported in Java EE 6.
    public boolean isSessionHijackDetected() {
        return FacesContext.getCurrentInstance().getExternalContext()
                .getSessionMap().get(SessionHijackingFilter.OCTOPUS_SESSION_HIJACKING_ATTEMPT) != null;
    }

}
