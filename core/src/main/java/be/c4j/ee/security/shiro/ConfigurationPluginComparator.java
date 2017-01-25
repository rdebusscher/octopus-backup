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

import be.c4j.ee.security.config.ConfigurationPlugin;
import be.c4j.ee.security.config.PluginOrder;

import java.util.Comparator;

/**
 *
 */
public class ConfigurationPluginComparator implements Comparator<ConfigurationPlugin> {
    @Override
    public int compare(ConfigurationPlugin cp1, ConfigurationPlugin cp2) {
        Integer order1 = getOrder(cp1);
        Integer order2 = getOrder(cp2);
        return order1.compareTo(order2);
    }

    private Integer getOrder(ConfigurationPlugin configurationPlugin) {
        int result = 1000;
        Class<? extends ConfigurationPlugin> aClass = configurationPlugin.getClass();
        PluginOrder order = aClass.getAnnotation(PluginOrder.class);
        if (order == null && aClass.getSuperclass() != null) {
            // When we have a proxy, we have to check the superclass.
            order = aClass.getSuperclass().getAnnotation(PluginOrder.class);
        }
        if (order != null) {
            result = order.value();
        }
        return result;
    }
}
