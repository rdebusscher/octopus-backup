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
package be.c4j.ee.security.filter.shiro;

import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;

import javax.servlet.FilterConfig;

/**
 */

public class OctopusFilterChainManager extends DefaultFilterChainManager {

    public OctopusFilterChainManager() {
        super();
    }

    public OctopusFilterChainManager(FilterConfig filterConfig) {
        super(filterConfig);
    }

    @Override
    protected String[] splitChainDefinition(String chainDefinition) {
        return super.splitChainDefinition("ef, " + chainDefinition);
    }
}
