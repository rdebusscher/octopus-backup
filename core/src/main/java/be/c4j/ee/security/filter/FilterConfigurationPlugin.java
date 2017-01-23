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
package be.c4j.ee.security.filter;

import be.c4j.ee.security.config.ConfigurationPlugin;
import be.c4j.ee.security.config.PluginOrder;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.web.servlet.AdviceFilter;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
@PluginOrder(80)
public class FilterConfigurationPlugin implements ConfigurationPlugin {


    private List<GlobalFilterConfiguration> globalFilterConfigurations;

    @PostConstruct
    public void init() {
        globalFilterConfigurations = BeanProvider.getContextualReferences(GlobalFilterConfiguration.class, true);
    }

    @Override
    public void addConfiguration(Ini ini) {

        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        for (GlobalFilterConfiguration globalFilterConfiguration : globalFilterConfigurations) {
            for (Map.Entry<String, Class<? extends AdviceFilter>> entry : globalFilterConfiguration.getGlobalFilters().entrySet()) {
                mainSection.put(entry.getKey(), entry.getValue().getName());
            }
        }
    }
}
