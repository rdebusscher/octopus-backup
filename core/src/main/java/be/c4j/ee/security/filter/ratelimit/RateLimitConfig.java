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
package be.c4j.ee.security.filter.ratelimit;

import be.c4j.ee.security.exception.OctopusConfigurationException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 */

public class RateLimitConfig {

    private static final Pattern CONFIG_PATTERN = Pattern.compile("(\\d+)/(\\d+)(s|m|h)");

    public FixedBucket createRateLimiter(String config) {
        Matcher matcher = CONFIG_PATTERN.matcher(config);
        if (!matcher.matches()) {
            throw new OctopusConfigurationException(String.format("Rate limit filter configuration '%s' is not valid, see documentation", config));
        }

        FixedBucket result = new FixedBucket();
        result.setAllowedRequests(Integer.valueOf(matcher.group(1)));
        String timeUnit = matcher.group(3);
        if ("s".equals(timeUnit)) {
            result.setDuration(Integer.valueOf(matcher.group(2)));
        }
        if ("m".equals(timeUnit)) {
            result.setDuration(Integer.valueOf(matcher.group(2)) * 60);
        }
        if ("h".equals(timeUnit)) {
            result.setDuration(Integer.valueOf(matcher.group(2)) * 3600);
        }

        result.setTokenStore(new HashMapTokenStore());

        return result;
    }
}
