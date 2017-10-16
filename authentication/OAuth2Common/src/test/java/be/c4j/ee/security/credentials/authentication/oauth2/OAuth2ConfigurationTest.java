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
package be.c4j.ee.security.credentials.authentication.oauth2;

import be.c4j.ee.security.credentials.authentication.oauth2.filter.AbstractOAuth2AuthcFilter;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.servlet.OAuth2CallbackProcessor;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.util.StringUtil;
import be.c4j.test.TestConfigSource;
import be.c4j.test.util.BeanManagerFake;
import be.c4j.test.util.ReflectionUtil;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */

@RunWith(MockitoJUnitRunner.class)
public class OAuth2ConfigurationTest {

    @Mock
    private OAuth2ProviderMetaDataControl oAuth2ProviderMetaDataControlMock;

    @Mock
    private DefaultOauth2ServletInfo servletInfoMock;

    @InjectMocks
    private OAuth2Configuration configuration;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() throws IllegalAccessException {
        ReflectionUtil.injectDependencies(configuration, new StringUtil());

        beanManagerFake = new BeanManagerFake();
    }

    @After
    public void tearDown() {
        ConfigResolver.freeConfigSources();
        beanManagerFake.deregistration();
    }

    @Test
    public void getClientId_singleProvider() {
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new TestOAuth2ProviderMetaData());

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("OAuth2.clientId", "testClientId");
        TestConfigSource.defineConfigValue(parameters);

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("testClientId");
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getClientId_singleProvider_noValue() {
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new TestOAuth2ProviderMetaData());

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<String, String>();
        TestConfigSource.defineConfigValue(parameters);

        configuration.getClientId();

    }

    @Test
    public void getClientId_multipleProvider_noSelection() {
        beanManagerFake.endRegistration();

        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new TestOAuth2ProviderMetaData("provider1"));
        metaDataList.add(new TestOAuth2ProviderMetaData("provider2"));

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("provider1.OAuth2.clientId", "testClientId");
        parameters.put("provider2.OAuth2.clientId", "test2ClientId");
        TestConfigSource.defineConfigValue(parameters);

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("provider1 : testClientId\nprovider2 : test2ClientId\n");
    }

    @Test
    public void getClientId_multipleProvider_withSelection() {
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new TestOAuth2ProviderMetaData("provider1"));
        metaDataList.add(new TestOAuth2ProviderMetaData("provider2"));

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("provider1.OAuth2.clientId", "testClientId");
        parameters.put("provider2.OAuth2.clientId", "test2ClientId");
        TestConfigSource.defineConfigValue(parameters);

        beanManagerFake.registerBean(servletInfoMock, DefaultOauth2ServletInfo.class);
        beanManagerFake.endRegistration();
        when(servletInfoMock.getUserProviderSelection()).thenReturn("provider2");

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("test2ClientId");
    }

    @Test
    public void getClientSecret_singleProvider() {
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new TestOAuth2ProviderMetaData());

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("OAuth2.clientSecret", "testClientSecret");
        TestConfigSource.defineConfigValue(parameters);

        String clientSecret = configuration.getClientSecret();
        assertThat(clientSecret).isEqualTo("testClientSecret");
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getClientSecret_singleProvider_noValue() {
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new TestOAuth2ProviderMetaData());

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<String, String>();
        TestConfigSource.defineConfigValue(parameters);

        configuration.getClientSecret();

    }

    @Test
    public void getClientSecret_multipleProvider_noSelection() {
        beanManagerFake.endRegistration();

        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new TestOAuth2ProviderMetaData("provider1"));
        metaDataList.add(new TestOAuth2ProviderMetaData("provider2"));

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("provider1.OAuth2.clientSecret", "testClientSecret");
        parameters.put("provider2.OAuth2.clientSecret", "test2ClientSecret");
        TestConfigSource.defineConfigValue(parameters);

        String clientSecret = configuration.getClientSecret();
        assertThat(clientSecret).isEqualTo("provider1 : testClientSecret\nprovider2 : test2ClientSecret\n");
    }

    @Test
    public void getClientSecret_multipleProvider_withSelection() {
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new TestOAuth2ProviderMetaData("provider1"));
        metaDataList.add(new TestOAuth2ProviderMetaData("provider2"));

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("provider1.OAuth2.clientSecret", "testClientSecret");
        parameters.put("provider2.OAuth2.clientSecret", "test2ClientSecret");
        TestConfigSource.defineConfigValue(parameters);

        beanManagerFake.registerBean(servletInfoMock, DefaultOauth2ServletInfo.class);
        beanManagerFake.endRegistration();
        when(servletInfoMock.getUserProviderSelection()).thenReturn("provider2");

        String clientSecret = configuration.getClientSecret();
        assertThat(clientSecret).isEqualTo("test2ClientSecret");
    }


    public static class TestOAuth2ProviderMetaData implements OAuth2ProviderMetaData {

        private String name;

        public TestOAuth2ProviderMetaData() {
        }

        public TestOAuth2ProviderMetaData(String name) {
            this.name = name;
        }

        @Override
        public String getServletPath() {
            return null;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public OAuth2InfoProvider getInfoProvider() {
            return null;
        }

        @Override
        public Class<? extends OAuth2CallbackProcessor> getCallbackProcessor() {
            return null;
        }

        @Override
        public Class<? extends AbstractOAuth2AuthcFilter> getOAuth2AuthcFilter() {
            return null;
        }
    }

}