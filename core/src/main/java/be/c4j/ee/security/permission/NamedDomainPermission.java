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
 *
 */
package be.c4j.ee.security.permission;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.apache.shiro.authz.permission.DomainPermission;

import java.util.List;
import java.util.Set;

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
        setParts(wildcardString.replaceAll(" ", ""));
        // Now call setXXX because we need to set the values also in those variables.
        List<Set<String>> parts = getParts();
        setDomain(parts.get(0).iterator().next());
        if (parts.size() > 1) {
            // In case we use just the name, not using the delimiters.

            setTargets(parts.get(2)); // This can't be the last call since there is an issue with setTargets. (alsways return in the middle
            // of the method and thus set parts not called and thus wrong values.
            // This is tested by be.c4j.ee.security.permission.NamedDomainPermissionTest.testBypassBugithinSetTargets()
            setActions(parts.get(1));
            this.name = someName;
        }
    }

    public String getName() {
        return name;
    }

    @Override
    public String name() {
        return name;
    }

    public String getWildcardNotation() {
        return getDomain() + PART_DIVIDER_TOKEN +
                collectionNotationFor(getActions()) + PART_DIVIDER_TOKEN +
                collectionNotationFor(getTargets());
    }

    private String collectionNotationFor(Set<String> entries) {
        StringBuilder result = new StringBuilder();
        for (String entry : entries) {
            if (result.length() > 0) {
                result.append(SUBPART_DIVIDER_TOKEN);
            }
            result.append(entry);
        }
        return result.toString();
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
