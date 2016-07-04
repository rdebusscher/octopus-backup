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

import java.util.Set;

public class NamedDomainPermission extends DomainPermission {

    private String name;

    public NamedDomainPermission(String someName, String someDomain, String actions, String targets) {
        super(actions, targets);
        setDomain(someDomain);
        if (someName == null || someName.trim().length() == 0) {
            throw new OctopusConfigurationException("Named permission can't be null or empty");
        }
        name = someName;
    }

    public String getName() {
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
}
