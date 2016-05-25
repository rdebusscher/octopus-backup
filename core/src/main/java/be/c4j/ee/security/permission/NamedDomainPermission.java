/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.permission;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.apache.shiro.authz.permission.DomainPermission;

public class NamedDomainPermission extends DomainPermission implements NamedPermission {

    private String name;

    public NamedDomainPermission(String someName, String someDomain, String actions, String targets) {
        super(actions, targets);
        setDomain(someDomain);
        if (someName == null || someName.trim().length() == 0) {
            throw new OctopusConfigurationException("Named permission can't be null or empty");
        }
        name = someName;
    }

    /**
     * When we need to create the the NamedDomainPermission based on a name and a wildcardString of Shiro. For example Department:create:* as wildcard string.
     *
     * @param someName
     * @param wildcardString
     */
    public NamedDomainPermission(String someName, String wildcardString) {
        setParts(wildcardString);
        this.name = someName;
    }

    public String getName() {
        return name;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof NamedDomainPermission)) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }

        NamedDomainPermission that = (NamedDomainPermission) o;

        return name.equals(that.name);

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + name.hashCode();
        return result;
    }
}
