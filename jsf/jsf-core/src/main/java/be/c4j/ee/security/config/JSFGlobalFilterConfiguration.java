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
package be.c4j.ee.security.config;

import be.c4j.ee.security.filter.GlobalFilterConfiguration;
import be.c4j.ee.security.filter.SessionHijackingFilter;
import org.apache.shiro.web.servlet.AdviceFilter;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.*;

/**
 *
 */
@ApplicationScoped
public class JSFGlobalFilterConfiguration implements GlobalFilterConfiguration {

    @Inject
    private OctopusJSFConfig octopusJSFConfig;

    private List<String> filters;

    @PostConstruct
    public void init() {
        filters = new ArrayList<String>();
        filters.add("sh");
    }

    @Override
    public Map<String, Class<? extends AdviceFilter>> getGlobalFilters() {
        Map<String, Class<? extends AdviceFilter>> result = new HashMap<String, Class<? extends AdviceFilter>>();
        // Only add the Session Hijacking filter when the developer didn't switch the feature off.
        if (octopusJSFConfig.getSessionHijackingLevel() != SessionHijackingLevel.OFF) {
            result.put("sh", SessionHijackingFilter.class);
        }
        return result;
    }

    @Override
    public List<String> addFiltersTo(String url) {
        if (octopusJSFConfig.getSessionHijackingLevel() != SessionHijackingLevel.OFF) {
            return filters;
        } else {
            return Collections.emptyList();
        }
    }
}
