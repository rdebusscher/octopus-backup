package be.c4j.ee.security;

import org.apache.myfaces.extensions.cdi.core.api.config.AbstractAttributeAware;
import org.apache.myfaces.extensions.cdi.core.api.config.CodiConfig;
import org.apache.myfaces.extensions.cdi.core.api.config.ConfigEntry;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

@ApplicationScoped
public class SecurityModuleConfig extends AbstractAttributeAware implements CodiConfig {

    private Properties configProperties;

    protected SecurityModuleConfig() {

    }


    @PostConstruct
    public void init() {
        configProperties = new Properties();
        try {
            InputStream resourceStream = SecurityModuleConfig.class.getClassLoader()
                                                                   .getResourceAsStream("securityModuleConfig" +
                                                                           ".properties");
            if (resourceStream != null) {
                configProperties.load(resourceStream);
            }
        } catch (IOException e) {
            ;
        }

    }

    @ConfigEntry
    public String getLocationSecuredURLProperties() {
        return configProperties.getProperty("securedURLs.file", "/WEB-INF/securedURLs.ini");
    }

}
