/*
 * Copyright 2014-2018 Rudy De Busscher (www.c4j.be)
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

import be.c4j.ee.security.exception.OctopusIllegalActionException;
import be.c4j.ee.security.util.StringUtil;
import be.c4j.test.util.ReflectionUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultOauth2ServletInfoTest {

    @Mock
    private OAuth2Configuration oAuth2ConfigurationMock;

    @Mock
    private OAuth2ProviderMetaDataControl oAuth2ProviderMetaDataControlMock;

    @InjectMocks
    private DefaultOauth2ServletInfo defaultOauth2ServletInfo;

    @Before
    public void setup() throws IllegalAccessException {
        ReflectionUtil.injectDependencies(defaultOauth2ServletInfo, new StringUtil());
    }

    @Test
    public void getServletPath_scenario1() {
        // no selection, Single Provider
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new OAuth2ConfigurationTest.TestOAuth2ProviderMetaData("test", "test"));
        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        defaultOauth2ServletInfo.init();

        String path = defaultOauth2ServletInfo.getServletPath();
        assertThat(path).isEqualTo("test");
    }

    @Test
    public void getServletPath_scenario2() {
        // no selection, Multiple Provider
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new OAuth2ConfigurationTest.TestOAuth2ProviderMetaData("test", "test"));
        metaDataList.add(new OAuth2ConfigurationTest.TestOAuth2ProviderMetaData("real", "real"));
        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        when(oAuth2ConfigurationMock.getOAuth2ProviderSelectionPage()).thenReturn("selectionPage");
        defaultOauth2ServletInfo.init();

        String path = defaultOauth2ServletInfo.getServletPath();
        assertThat(path).isEqualTo("selectionPage");
    }

    @Test
    public void getServletPath_scenario3() throws IllegalAccessException {
        // selection made, Multiple Provider
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new OAuth2ConfigurationTest.TestOAuth2ProviderMetaData("test", "test"));
        metaDataList.add(new OAuth2ConfigurationTest.TestOAuth2ProviderMetaData("real", "real"));
        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        defaultOauth2ServletInfo.init();

        ReflectionUtil.injectDependencies(defaultOauth2ServletInfo, "real");
        String path = defaultOauth2ServletInfo.getServletPath();
        assertThat(path).isEqualTo("real");
    }

    @Test(expected = OctopusIllegalActionException.class)
    public void getServletPath_scenario4() throws IllegalAccessException {
        // selection made, Multiple Provider, unknown value
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new OAuth2ConfigurationTest.TestOAuth2ProviderMetaData("test", "test"));
        metaDataList.add(new OAuth2ConfigurationTest.TestOAuth2ProviderMetaData("real", "real"));
        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        defaultOauth2ServletInfo.init();

        ReflectionUtil.injectDependencies(defaultOauth2ServletInfo, "wrong");

        defaultOauth2ServletInfo.getServletPath();

    }
}