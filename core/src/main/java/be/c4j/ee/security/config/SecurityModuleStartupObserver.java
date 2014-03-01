package be.c4j.ee.security.config;

import org.apache.myfaces.extensions.cdi.core.api.startup.event.StartupEvent;
import org.apache.myfaces.extensions.cdi.core.impl.AbstractStartupObserver;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import java.util.logging.Level;

@ApplicationScoped
public class SecurityModuleStartupObserver extends AbstractStartupObserver {

    @Inject
    private SecurityModuleConfig securityModuleConfig;

    protected SecurityModuleStartupObserver() {
    }

    protected void logSecurityModuleConfiguration(@Observes StartupEvent startupEvent) {
        try {
            StringBuilder info = new StringBuilder("[Started] Octopus framework (C4J) ");
            info.append(separator);

            //module config
            info.append(getConfigInfo(securityModuleConfig));
            logger.info(info.toString());
        }
        //avoid that this log harms the startup
        catch (Exception e) {
            logger.log(Level.WARNING,
                    "Octopus Module couldn't log the current configuration. Startup will continue!", e);
        }

    }

}
