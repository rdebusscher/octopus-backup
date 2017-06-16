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
package be.c4j.ee.security.authentication.cas.info;

import be.c4j.ee.security.authentication.cas.CasSEConfiguration;
import be.c4j.ee.security.authentication.cas.exception.CasAuthenticationException;
import be.c4j.ee.security.authentication.credentials.authentication.cas.CasUser;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class CasInfoProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(CasInfoProvider.class);

    private CasSEConfiguration casConfiguration;

    private TicketValidator ticketValidator;

    public CasInfoProvider() {
        // Within the cas module, we create a producer for this class which we inject at some places.
        // But this means that the class must be conform the CDI rules and that means a non arg constructor
        // even if CDI doesn't instantiate instances.
    }

    public CasInfoProvider(CasSEConfiguration casConfiguration) {
        this.casConfiguration = casConfiguration;
        init();
    }

    private void init() {
        String urlPrefix = casConfiguration.getSSOServer();

        switch (casConfiguration.getCASProtocol()) {

            case CAS:
                ticketValidator = new Cas30ServiceTicketValidator(urlPrefix);
                break;

            case SAML:
                ticketValidator = new Saml11TicketValidator(urlPrefix);
                break;
        }

    }

    public CasUser retrieveUserInfo(String ticket) {
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

            Map<String, Object> info = new HashMap<String, Object>();
            for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                if (entry.getValue() instanceof Serializable) {
                    info.put(entry.getKey(), entry.getValue());
                }
            }

            result.setUserInfo(info);

        } catch (TicketValidationException e) {
            LOGGER.error("Validating CAS Ticket failed", e);
            throw new CasAuthenticationException(e);
        }
        return result;
    }
}
