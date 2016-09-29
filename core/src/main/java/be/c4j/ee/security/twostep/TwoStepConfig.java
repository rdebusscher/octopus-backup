package be.c4j.ee.security.twostep;

import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class TwoStepConfig extends AbstractOctopusConfig implements ModuleConfig {

    private boolean twoStepAuthenticationProviderFound;

    @PostConstruct
    public void init() {
        defineConfigurationSources();
        List<TwoStepProvider> references = BeanProvider.getContextualReferences(TwoStepProvider.class, true);
        twoStepAuthenticationProviderFound = !references.isEmpty();
    }

    // TODO Is this usefull?
    @ConfigEntry
    public boolean getTwoStepAuthenticationActive() {
        return twoStepAuthenticationProviderFound;
    }

    @ConfigEntry
    public Boolean getAlwaysTwoStepAuthentication() {
        Boolean result = null;
        if (twoStepAuthenticationProviderFound) {
            String value = ConfigResolver.getPropertyValue("2step.always", "true");
            result = Boolean.valueOf(value);
        }
        return result;
    }

}
