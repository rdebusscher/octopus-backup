package be.c4j.ee.security.config;

import be.c4j.ee.security.shiro.FacesAjaxAwareUserFilter;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class JSFConfiguration implements ConfigurationPlugin {

    @Inject
    private OctopusConfig config;

    @Override
    public void addConfiguration(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("user", FacesAjaxAwareUserFilter.class.getName());
        mainSection.put("user.loginUrl", config.getLoginPage());

    }
}
