package be.c4j.ee.security.twostep.otp.config;

import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class OTPConfig extends AbstractOctopusConfig implements ModuleConfig {

    @PostConstruct
    public void init() {
        defineConfigurationSources();
    }

    @ConfigEntry
    public String getOTPProvider() {
        return ConfigResolver.getPropertyValue("otp.provider", "DOTP");
    }

    @ConfigEntry
    public String getOTPConfigFile() {
        return ConfigResolver.getPropertyValue("otp.configFile", null);
    }

    @ConfigEntry
    public int getOTPLength() {
        int result;
        String value = ConfigResolver.getPropertyValue("otp.length", "6");
        try {
            result = Integer.valueOf(value);
        } catch (NumberFormatException e) {
            throw new OctopusConfigurationException("otp.length property must be numeric (Integer)");
        }
        return result;
    }
}
