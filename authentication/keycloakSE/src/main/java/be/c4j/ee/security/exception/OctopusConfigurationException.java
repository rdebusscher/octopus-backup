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
 *
 */
package be.c4j.ee.security.exception;

import org.apache.shiro.authc.AuthenticationException;

/**
 * FIXME Duplicate!! We need a core-SE module. Which also contains handy methods for SE environment
 * Also config, logging of config, ...
 */
public class OctopusConfigurationException extends AuthenticationException {

    public OctopusConfigurationException(String message) {
        super("Octopus Configuration exception: " + message);
    }
}
