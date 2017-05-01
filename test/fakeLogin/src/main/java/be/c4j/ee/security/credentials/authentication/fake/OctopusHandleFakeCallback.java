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
package be.c4j.ee.security.credentials.authentication.fake;

import be.c4j.ee.security.credentials.authentication.oauth2.fake.FakeCallbackHandler;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * FIXME Functionality broken due to the removal of aplicationName and customCallbackHandler
 */
@ApplicationScoped
public class OctopusHandleFakeCallback implements FakeCallbackHandler {

    @Inject
    private Logger logger;

    @Inject
    private OAuth2TokenStore tokenStore;

    public void doAuthenticate(HttpServletRequest request, HttpServletResponse response) throws IOException {
        throw new OctopusConfigurationException("FIXME now that we have removed some functionality");

    }
}
