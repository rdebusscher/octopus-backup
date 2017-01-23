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
 *
 */
package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.LinkedinProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.json.LinkedinJSONProcessor;
import be.c4j.ee.security.credentials.authentication.oauth2.provider.LinkedinOAuth2ServiceProducer;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Token;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuthService;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
@LinkedinProvider
public class LinkedinInfoProvider implements OAuth2InfoProvider {

    @Inject
    private LinkedinOAuth2ServiceProducer linkedOAuth2ServiceProducer;

    @Inject
    private LinkedinJSONProcessor jsonProcessor;

    @Override
    public OAuth2User retrieveUserInfo(Token token, HttpServletRequest req) {

        // No state here so token can be null.
        OAuthService authService = linkedOAuth2ServiceProducer.createOAuthService(req, null);
        OAuthRequest oReq = new OAuthRequest(Verb.GET, "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,picture-url,public-profile-url,email-address)?format=json", authService);

        authService.signRequest(token, oReq);
        Response oResp = oReq.send();
        OAuth2User oAuth2User = jsonProcessor.extractLinkedinUser(oResp.getBody());
        if (oAuth2User != null) {
            oAuth2User.setToken(token);
        }

        return oAuth2User;

    }
}
