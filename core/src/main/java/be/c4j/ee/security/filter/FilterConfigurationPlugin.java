package be.c4j.ee.security.filter;

import be.c4j.ee.security.config.ConfigurationPlugin;
import be.c4j.ee.security.config.PluginOrder;
import be.c4j.ee.security.shiro.OctopusUserFilter;
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
