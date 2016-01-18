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
package be.c4j.demo.security.demo.model;

import be.c4j.ee.security.permission.NamedPermission;

/**
 * This is an entity object in production type application
 */
public class HRAppPermission implements NamedPermission {

    private String name;
    private String domain;
    private String actions;
    private String target;

    public HRAppPermission(String name, String domain, String actions, String target) {
        this.name = name;
        this.domain = domain;
        this.actions = actions;
        this.target = target;
    }

    public String getName() {
        return name;
    }

    @Override
    public String name() {
        return getName();
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getActions() {
        return actions;
    }

    public void setActions(String actions) {
        this.actions = actions;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getDomainPermissionRepresentation() {
        StringBuilder result = new StringBuilder();
        result.append(domain).append(':').append(actions).append(':').append(target);
        return result.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        HRAppPermission that = (HRAppPermission) o;

        if (!name.equals(that.name)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
}
