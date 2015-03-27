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
package be.c4j.ee.security.permission;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.inject.Typed;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Typed
public class PermissionLookup<T extends Enum<T>> {

    private static final Logger LOGGER = LoggerFactory.getLogger(PermissionLookup.class);

    private Map<T, NamedDomainPermission> map;  // for holding the mapping between the two

    private Class<T> enumClazz;

    public PermissionLookup() {
        // although this bean is excluded, Weld (Glassfish 3.1.2.2) wants it to have a no arg constructor.
    }

    public PermissionLookup(List<NamedDomainPermission> allPermission, Class<T> clazz) {
        enumClazz = clazz;
        map = new EnumMap<T, NamedDomainPermission>(clazz);
        // map the lookups together
        for (NamedDomainPermission item : allPermission) {
            T key;
            try {
                key = Enum.valueOf(clazz, item.getName());
                map.put(key, item);
            } catch (IllegalArgumentException e) {
                LOGGER.info("There is no type safe equivalent and CDI Bean for named permission "+item.getName());
            }
        }
    }

    public NamedDomainPermission getPermission(T permissionCode) {
        return map.get(permissionCode);
    }

    public NamedDomainPermission getPermission(String namedPermission) {
        return getPermission(Enum.valueOf(enumClazz, namedPermission));
    }
}

