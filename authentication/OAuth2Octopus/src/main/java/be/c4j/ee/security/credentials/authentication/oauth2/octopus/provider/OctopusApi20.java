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
package be.c4j.ee.security.credentials.authentication.oauth2.octopus.provider;

import be.c4j.ee.security.credentials.authentication.oauth2.octopus.config.OctopusServerConfig;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.extractors.OAuth2AccessTokenJsonExtractor;
import com.github.scribejava.core.extractors.TokenExtractor;
import com.github.scribejava.core.model.OAuth2AccessToken;
import org.apache.deltaspike.core.api.provider.BeanProvider;

public class OctopusApi20 extends DefaultApi20 {

    private OctopusServerConfig octopusServerConfig;

    protected OctopusApi20() {
        octopusServerConfig = BeanProvider.getContextualReference(OctopusServerConfig.class);
    }

    private static class InstanceHolder {
        private static final OctopusApi20 INSTANCE = new OctopusApi20();
    }

    public static OctopusApi20 instance() {
        return InstanceHolder.INSTANCE;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return octopusServerConfig.getOctopusServerRoot() + "/octopus/sso/token";
    }

    @Override
    protected String getAuthorizationBaseUrl() {
        return octopusServerConfig.getOctopusServerRoot() + "/octopus/sso/authenticate";
    }

    @Override
    public TokenExtractor<OAuth2AccessToken> getAccessTokenExtractor() {
        return OAuth2AccessTokenJsonExtractor.instance();
    }
}
