/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.credentials.authentication.cas;

import be.c4j.ee.security.credentials.authentication.cas.config.CasConfiguration;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class CasConfigurationHelper {

    @Inject
    private Logger logger;

    @Inject
    private CasConfiguration casConfiguration;

    private boolean loginUrlDefined = false;
    private String casService;
    private String loginUrl;

    public String defineCasLoginURL(HttpServletRequest request) {
        if (!loginUrlDefined) {
            defineLoginURL(request);
            loginUrlDefined = true;
            logger.info("CAS service = " + casService);
            casConfiguration.setCasService(casService);
        }
        return loginUrl;
    }

    private void defineLoginURL(HttpServletRequest request) {
        StringBuilder result = new StringBuilder();
        String ssoServer = casConfiguration.getSSOServer();
        result.append(ssoServer);
        if (!ssoServer.endsWith("/")) {
            result.append("/");
        }
        result.append("login?service=");

        casService = assembleCallbackUrl(request);
        result.append(casService);

        loginUrl = result.toString();
    }

    private String assembleCallbackUrl(HttpServletRequest req) {
        StringBuilder result = new StringBuilder();
        result.append(req.getScheme()).append("://");
        result.append(req.getServerName()).append(':');
        result.append(req.getServerPort());
        result.append(req.getContextPath()).append("/cas-callback");
        return result.toString();
    }
}
