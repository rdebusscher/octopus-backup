package be.c4j.ee.security.credentials.authentication.cas;

import be.c4j.ee.security.credentials.authentication.cas.config.CasConfiguration;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class CasInfoProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(CasInfoProvider.class);
    @Inject
    private CasConfiguration casConfiguration;

    private TicketValidator ticketValidator;

    @PostConstruct
    public void init() {
        String urlPrefix = casConfiguration.getSSOServer();
        if ("saml".equalsIgnoreCase(casConfiguration.getCASProtocol())) {
            ticketValidator = new Saml11TicketValidator(urlPrefix);
        } else {

            ticketValidator = new Cas20ServiceTicketValidator(urlPrefix);
        }
    }

    public CasUser retrieveUserInfo(String ticket, HttpServletRequest req) {
        CasUser result = new CasUser(ticket);

        try {
            // contact CAS server to validate service ticket
            Assertion casAssertion = ticketValidator.validate(ticket, casConfiguration.getCASService());
            // get principal, user id and attributes
            AttributePrincipal casPrincipal = casAssertion.getPrincipal();
            String userId = casPrincipal.getName();

            result.setUserName(userId);
            /*
            FIXME
            log.debug("Validate ticket : {} in CAS server : {} to retrieve user : {}", new Object[]{
                    ticket, getCasServerUrlPrefix(), userId
            });
            */

            Map<String, Object> attributes = casPrincipal.getAttributes();

            // FIXME email -> needs to be configurable
            result.setEmail((String) attributes.get("email"));

            Map<Serializable, Serializable> info = new HashMap<Serializable, Serializable>();
            for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                if (entry.getValue() instanceof Serializable) {
                    info.put(entry.getKey(), (Serializable) entry.getValue());
                }
            }

            result.setUserInfo(info);

            /*
            String rememberMeAttributeName = getRememberMeAttributeName();
            String rememberMeStringValue = (String) attributes.get(rememberMeAttributeName);
            boolean isRemembered = rememberMeStringValue != null && Boolean.parseBoolean(rememberMeStringValue);
            if (isRemembered) {
                casToken.setRememberMe(true);
            }
            */


        } catch (TicketValidationException e) {
            LOGGER.error("Validating CAS Ticket failed", e);
        }
        return result;
    }
}
