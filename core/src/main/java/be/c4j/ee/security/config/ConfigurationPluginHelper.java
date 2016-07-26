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
package be.c4j.ee.security.config;

import org.apache.shiro.config.Ini;

/**
 *
 */
public final class ConfigurationPluginHelper {

    private ConfigurationPluginHelper() {
    }

    public static void addToList(Ini ini, String sectionName, String key, String value) {
        Ini.Section section = ini.get(sectionName);
        String currentValue = section.get(key);
        if (currentValue == null) {
            section.put(key, value);
        } else {
            section.put(key, currentValue + "," + value);
        }
    }
}
