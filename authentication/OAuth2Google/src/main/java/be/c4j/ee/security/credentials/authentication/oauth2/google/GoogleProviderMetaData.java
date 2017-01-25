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
package be.c4j.ee.security.credentials.authentication.oauth2.google;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2ProviderMetaData;
import be.c4j.ee.security.credentials.authentication.oauth2.filter.AbstractOAuth2AuthcFilter;
import be.c4j.ee.security.credentials.authentication.oauth2.google.filter.GoogleAuthcFilter;
import be.c4j.ee.security.credentials.authentication.oauth2.google.servlet.GoogleOAuth2CallbackProcessor;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.servlet.OAuth2CallbackProcessor;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class GoogleProviderMetaData implements OAuth2ProviderMetaData {

    @Inject
    @GoogleProvider
    private OAuth2InfoProvider infoProvider;

    @Override
    public String getServletPath() {
        return "/googleplus";
    }

    @Override
    public String getName() {
        return "Google";
    }

    @Override
    public OAuth2InfoProvider getInfoProvider() {
        return infoProvider;
    }

    @Override
    public Class<? extends OAuth2CallbackProcessor> getCallbackProcessor() {
        return GoogleOAuth2CallbackProcessor.class;
    }

    @Override
    public Class<? extends AbstractOAuth2AuthcFilter> getOAuth2AuthcFilter() {
        return GoogleAuthcFilter.class;
    }
}
