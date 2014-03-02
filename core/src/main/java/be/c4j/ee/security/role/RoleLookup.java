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
package be.c4j.ee.security.role;

import javax.enterprise.inject.Typed;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
@Typed
public class RoleLookup <T extends Enum<T>> {
    private Map<T, NamedApplicationRole> map;  // for holding the mapping between the two

    private Class<T> enumClazz;

    public RoleLookup() {
        // although this bean is excluded, Weld (Glassfish 3.1.2.2) wants it to have a no arg constructor.
    }

    public RoleLookup(List<NamedApplicationRole> allRoles, Class<T> clazz) {
        enumClazz = clazz;
        map = new EnumMap<T, NamedApplicationRole>(clazz);
        // map the lookups together
        for (NamedApplicationRole item : allRoles) {
            T key = Enum.valueOf(clazz, item.getRoleName());
            map.put(key, item);
        }
    }

    public NamedApplicationRole getRole(T roleName) {
        return map.get(roleName);
    }

    public NamedApplicationRole getRole(String roleName) {
        return getRole(Enum.valueOf(enumClazz, roleName));
    }
}

