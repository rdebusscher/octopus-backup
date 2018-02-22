/*
 * Copyright 2014-2018 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CookieAgeConfig {

    private static final Pattern CONFIG_PATTERN = Pattern.compile("(\\d+)(h|d)");

    public int getCookieAge(String config) {
        int result = -1;
        Matcher matcher = CONFIG_PATTERN.matcher(config);
        if (!matcher.matches()) {
            throw new OctopusConfigurationException(String.format("Remember-me Cookie age configuration '%s' is not valid, see documentation", config));
        }

        String timeUnit = matcher.group(2);
        if ("h".equals(timeUnit)) {
            result = Integer.valueOf(matcher.group(1)) * 3600;
        }

        if ("d".equals(timeUnit)) {
            result = Integer.valueOf(matcher.group(1)) * 3600  * 24;
        }

        return result;
    }

}
