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
package be.c4j.ee.security.shiro;

import be.c4j.ee.security.permission.NamedPermission;
import org.apache.shiro.config.Ini;

import javax.enterprise.context.Dependent;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Dependent
public class URLPermissionProtector {

    private Ini.Section section;

    public void addURLs() {

    }

    protected void addSecuredURL(String url, NamedPermission namedPermission) {
        section.put(url, "user, np[" + namedPermission.name() + "]");
    }

    protected void addSecuredURL(String url, Set<NamedPermission> namedPermissions) {
        StringBuilder value = new StringBuilder();
        boolean first = true;
        value.append("user, np[");
        for (NamedPermission permission : namedPermissions) {
            if (!first) {
                value.append(',');
            }
            value.append(permission.name());
            first = false;
        }
        section.put(url, value.toString());
    }

    protected void addSecuredURL(String url, NamedPermission... namedPermissions) {
        addSecuredURL(url, new HashSet<NamedPermission>(Arrays.asList(namedPermissions)));
    }

    public void configurePermissions(Ini.Section section) {
        this.section = section;
        addURLs();
    }

}
