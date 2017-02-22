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
package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.LinkedinProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.json.LinkedinJSONProcessor;
import be.c4j.ee.security.credentials.authentication.oauth2.provider.LinkedinOAuth2ServiceProducer;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

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
    public OAuth2User retrieveUserInfo(OAuth2AccessToken token, HttpServletRequest req) {

        // No state here so token can be null.
        OAuth20Service authService = linkedOAuth2ServiceProducer.createOAuthService(req, null);
        OAuthRequest request = new OAuthRequest(Verb.GET, "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,picture-url,public-profile-url,email-address)?format=json");

        authService.signRequest(token, request);
        OAuth2User oAuth2User;
        try {
            Response oResp = authService.execute(request);
            oAuth2User = jsonProcessor.extractLinkedinUser(oResp.getBody());
            if (oAuth2User != null) {
                oAuth2User.setToken(token);
            }

        } catch (InterruptedException e) {
            throw new OctopusUnexpectedException(e);
        } catch (ExecutionException e) {
            throw new OctopusUnexpectedException(e);
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }
        return oAuth2User;

    }
}
