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
package be.c4j.ee.security.jwt.config;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class MappingSystemAccountToApiKeyTest {


    @Mock
    private SCSConfig SCSConfigMock;

    @InjectMocks
    private MappingSystemAccountToApiKey mapping;

    @Test
    public void getAccountList() {

        when(SCSConfigMock.getSystemAccountsMapFile()).thenReturn("MappingSystemAccountToApiKey.properties");

        mapping.init();

        assertThat(mapping.isSystemAccountUsageActive()).isTrue();
        assertThat(mapping.containsOnlyOneMapping()).isFalse();
        assertThat(mapping.getAccountList("key2")).containsExactly("account2", "account3");
    }

    @Test
    public void getAccountList_nonExisting() {

        when(SCSConfigMock.getSystemAccountsMapFile()).thenReturn("MappingSystemAccountToApiKey.properties");

        mapping.init();

        assertThat(mapping.isSystemAccountUsageActive()).isTrue();
        assertThat(mapping.containsOnlyOneMapping()).isFalse();
        assertThat(mapping.getAccountList("key3")).isNull();
    }

    @Test
    public void getApiKey() {

        when(SCSConfigMock.getSystemAccountsMapFile()).thenReturn("MappingSystemAccountToApiKey.properties");

        mapping.init();

        assertThat(mapping.isSystemAccountUsageActive()).isTrue();
        assertThat(mapping.containsOnlyOneMapping()).isFalse();
        assertThat(mapping.getApiKey("account2")).isEqualTo("key2");
    }

    @Test
    public void getApiKey_scenario2() {

        when(SCSConfigMock.getSystemAccountsMapFile()).thenReturn("MappingSystemAccountToApiKey.properties");

        mapping.init();

        assertThat(mapping.isSystemAccountUsageActive()).isTrue();
        assertThat(mapping.containsOnlyOneMapping()).isFalse();
        assertThat(mapping.getApiKey("account1")).isEqualTo("key1");
    }

    @Test
    public void getApiKey_nonExisting() {

        when(SCSConfigMock.getSystemAccountsMapFile()).thenReturn("MappingSystemAccountToApiKey.properties");

        mapping.init();

        assertThat(mapping.isSystemAccountUsageActive()).isTrue();
        assertThat(mapping.containsOnlyOneMapping()).isFalse();
        assertThat(mapping.getApiKey("account4")).isNull();
    }

    @Test
    public void getOnlyAccount() {
        when(SCSConfigMock.getSystemAccountsMapFile()).thenReturn("MappingSystemAccountToApiKey_v2.properties");

        mapping.init();

        assertThat(mapping.isSystemAccountUsageActive()).isTrue();
        assertThat(mapping.containsOnlyOneMapping()).isTrue();
        assertThat(mapping.getOnlyAccount()).isEqualTo("account4");
    }

    @Test
    public void isSystemAccountUsageActive() {
        when(SCSConfigMock.getSystemAccountsMapFile()).thenReturn(null);

        mapping.init();

        assertThat(mapping.isSystemAccountUsageActive()).isFalse();
    }

}