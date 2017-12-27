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

import be.c4j.ee.security.util.StringUtil;
import be.c4j.test.util.BeanManagerFake;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class StringPermissionLookupFixture {

    public static void registerLookup(BeanManagerFake beanManagerFake) throws IllegalAccessException {
        List<NamedDomainPermission> allPermissions = new ArrayList<NamedDomainPermission>();
        allPermissions.add(new NamedDomainPermission("permission1", "SPermission:1:*"));
        allPermissions.add(new NamedDomainPermission("permission2", "SPermission:2:*"));
        allPermissions.add(new NamedDomainPermission("permission3", "SPermission:3:*"));
        StringPermissionLookup stringLookup = new StringPermissionLookup(allPermissions);
        beanManagerFake.registerBean(stringLookup, StringPermissionLookup.class);
        beanManagerFake.registerBean(new StringUtil(), StringUtil.class);
    }

}