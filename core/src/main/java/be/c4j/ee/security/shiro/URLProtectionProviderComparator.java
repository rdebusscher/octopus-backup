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
package be.c4j.ee.security.shiro;

import be.c4j.ee.security.url.ProgrammaticURLProtectionProvider;
import be.c4j.ee.security.url.URLProtectionProviderOrder;

import java.util.Comparator;

/**
 *
 */
public class URLProtectionProviderComparator implements Comparator<ProgrammaticURLProtectionProvider> {
    @Override
    public int compare(ProgrammaticURLProtectionProvider p1, ProgrammaticURLProtectionProvider p2) {
        Integer order1 = getOrder(p1);
        Integer order2 = getOrder(p2);
        return order1.compareTo(order2);
    }

    private Integer getOrder(ProgrammaticURLProtectionProvider protectionProvider) {
        int result = 1000;
        Class<? extends ProgrammaticURLProtectionProvider> aClass = protectionProvider.getClass();
        URLProtectionProviderOrder order = aClass.getAnnotation(URLProtectionProviderOrder.class);
        if (order == null && aClass.getSuperclass() != null) {
            // When we have a proxy, we have to check the superclass.
            order = aClass.getSuperclass().getAnnotation(URLProtectionProviderOrder.class);
        }
        if (order != null) {
            result = order.value();
        }
        return result;
    }
}
