package be.c4j.ee.security.session;

import be.c4j.ee.security.config.OctopusConfig;
import org.apache.shiro.SecurityUtils;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class SessionUtil {

    @Inject
    private OctopusConfig octopusConfig;

    public void invalidateCurrentSession(HttpServletRequest request) {
        if (!octopusConfig.getIsSessionInvalidatedAtLogin()) {
            // Defined with config that developer don't was logout/session invalidation.
            return;
        }

        HttpSession session = request.getSession();

        HashMap<String, Object> content = new HashMap<String, Object>();
        Enumeration keys = session.getAttributeNames();

        while (keys.hasMoreElements()) {
            String key = (String) keys.nextElement();
            content.put(key, session.getAttribute(key));
            session.removeAttribute(key);
        }

        SecurityUtils.getSubject().logout();

        session = request.getSession(true);
        for (Map.Entry m : content.entrySet()) {
            session.setAttribute((String) m.getKey(), m.getValue());
        }
        content.clear();
    }


}
