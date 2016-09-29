package be.c4j.ee.security.shiro;

import org.apache.shiro.config.Ini;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.config.WebIniSecurityManagerFactory;

/**
 *
 */
public class OctopusSecurityManagerFactory extends WebIniSecurityManagerFactory {

    public OctopusSecurityManagerFactory() {
        super();
    }

    public OctopusSecurityManagerFactory(Ini config) {
        super(config);
    }

    @Override
    protected SecurityManager createDefaultInstance() {
        return new OctopusSecurityManager();
    }
}
