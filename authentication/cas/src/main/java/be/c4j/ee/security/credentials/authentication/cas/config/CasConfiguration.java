package be.c4j.ee.security.credentials.authentication.cas.config;

import be.c4j.ee.security.config.OctopusConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.inject.Specializes;

/**
 *
 */
@Specializes
public class CasConfiguration extends OctopusConfig {

    private String casService;

    @Override
    public String getLoginPage() {
        return "DYNAMIC CAS BASED";
    }

    @ConfigEntry
    public String getSSOServer() {
        return ConfigResolver.getPropertyValue("SSO.server", "");
    }

    @ConfigEntry
    public String getCASProtocol() {
        return ConfigResolver.getPropertyValue("CAS.protocol", "CAS"); // SAML should also be supported
    }

    @ConfigEntry(value = "Determined later on, see log entry")
    public String getCASService() {
        return casService;
    }

    public void setCasService(String casService) {
        this.casService = casService;
    }
}
