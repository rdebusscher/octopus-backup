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
package be.c4j.ee.security.permission;

import be.c4j.ee.security.PublicAPI;

import javax.enterprise.inject.Typed;
import java.util.*;

/**
 *
 */
@Typed
@PublicAPI
public class StringPermissionLookup {

    private Map<String, NamedDomainPermission> map;

    public StringPermissionLookup() {
        // although this bean is excluded, Weld (Glassfish 3.1.2.2) wants it to have a no arg constructor.
        map = new HashMap<String, NamedDomainPermission>();
    }

    public StringPermissionLookup(List<NamedDomainPermission> allPermissions) {
        this();
        for (NamedDomainPermission item : allPermissions) {
            map.put(item.getName().toUpperCase(Locale.ENGLISH), item);
        }
    }

    public NamedDomainPermission getPermission(String namedPermission) {
        if (namedPermission == null || namedPermission.trim().isEmpty()) {
            throw new IllegalArgumentException("namedPermission value can't be null or empty.");
        }
        // namedPermission : a String indicating a named permission defined by the constructor, or a wildcardString
        String key = namedPermission.toUpperCase(Locale.ENGLISH);
        NamedDomainPermission result;
        if (map.containsKey(key)) {
            result = map.get(key);
        } else {
            result = new NamedDomainPermission(createNameForPermission(namedPermission), namedPermission);
        }
        return result;
    }

    public Collection<NamedDomainPermission> getAllPermissions() {
        return map.values();
    }

    public static String createNameForPermission(String wildCardString) {
        // TODO Do we need a customizeable factory so that developer can define how the names are created.
        StringBuilder result = new StringBuilder();
        String[] parts = wildCardString.split(":");
        for (String part : parts) {
            result.append(capitalize(part));
        }
        return result.toString();
    }

    private static String capitalize(String value) {
        String result;
        if (value.length() == 1) {
            result = value.toUpperCase(Locale.ENGLISH);
        } else {
            String s = value.toLowerCase(Locale.ENGLISH);

            result = Character.toUpperCase(s.charAt(0)) + s.substring(1);
        }
        return result;
    }

}
