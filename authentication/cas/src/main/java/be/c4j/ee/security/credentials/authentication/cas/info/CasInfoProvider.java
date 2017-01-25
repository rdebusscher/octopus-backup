/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.c4j.ee.security.credentials.authentication.cas.info;

import be.c4j.ee.security.credentials.authentication.cas.CasAuthenticationException;
import be.c4j.ee.security.credentials.authentication.cas.CasUser;
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

            Map<String, Object> attributes = casPrincipal.getAttributes();

            result.setEmail((String) attributes.get(casConfiguration.getCASEmailProperty()));

            Map<Serializable, Serializable> info = new HashMap<Serializable, Serializable>();
            for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                if (entry.getValue() instanceof Serializable) {
                    info.put(entry.getKey(), (Serializable) entry.getValue());
                }
            }

            result.setUserInfo(info);

            /*
             FIXME
            String rememberMeAttributeName = getRememberMeAttributeName();
            String rememberMeStringValue = (String) attributes.get(rememberMeAttributeName);
            boolean isRemembered = rememberMeStringValue != null && Boolean.parseBoolean(rememberMeStringValue);
            if (isRemembered) {
                casToken.setRememberMe(true);
            }
            */

        } catch (TicketValidationException e) {
            LOGGER.error("Validating CAS Ticket failed", e);
            throw new CasAuthenticationException(e);
        }
        return result;
    }
}
