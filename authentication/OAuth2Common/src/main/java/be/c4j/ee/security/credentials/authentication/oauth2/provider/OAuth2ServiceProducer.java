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
package be.c4j.ee.security.credentials.authentication.oauth2.provider;

import be.c4j.ee.security.credentials.authentication.oauth2.DefaultOauth2ServletInfo;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@Typed
public abstract class OAuth2ServiceProducer {

    @Inject
    private DefaultOauth2ServletInfo defaultOauth2ServletInfo;

    /**
     * @param req
     * @param csrfToken value for the state parameter, allowed to be null in case you don't need it
     * @return
     */
    public abstract OAuth20Service createOAuthService(HttpServletRequest req, String csrfToken);

    protected String assembleCallbackUrl(HttpServletRequest req) {
        StringBuilder result = new StringBuilder();
        result.append(req.getScheme()).append("://");
        result.append(req.getServerName()).append(':');
        result.append(req.getServerPort());
        result.append(req.getContextPath()).append("/oauth2callback");
        return result.toString();
    }

}
