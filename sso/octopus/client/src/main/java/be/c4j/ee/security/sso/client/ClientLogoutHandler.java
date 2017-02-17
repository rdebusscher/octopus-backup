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
package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.logout.LogoutHandler;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.inject.Specializes;
import javax.faces.context.ExternalContext;
import javax.inject.Inject;

/**
 *
 */
@Specializes
public class ClientLogoutHandler extends LogoutHandler {

    @Inject
    private OctopusSSOClientConfiguration clientConfiguration;

    private SSODataEncryptionHandler encryptionHandler;

    @PostConstruct
    public void init() {
        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);
    }


    @Override
    public String getLogoutPage(ExternalContext externalContext) {

        StringBuilder result = new StringBuilder();
        result.append(super.getLogoutPage(externalContext));

        String applicationName = clientConfiguration.getSSOApplication();

        if (encryptionHandler != null) {
            if (result.indexOf("?") == -1) {
                result.append('?');
            } else {
                result.append('&');
            }
            result.append("x-api-key=").append(clientConfiguration.getSSOApiKey());


            applicationName = encryptionHandler.encryptData(applicationName, clientConfiguration.getSSOApiKey());
        }
        if (result.indexOf("?") == -1) {
            result.append('?');
        } else {
            result.append('&');
        }
        result.append("application=").append(applicationName);

        return result.toString();
    }
}