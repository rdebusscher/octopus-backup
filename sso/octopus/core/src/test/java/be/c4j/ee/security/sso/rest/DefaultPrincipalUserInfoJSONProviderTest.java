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
package be.c4j.ee.security.sso.rest;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class DefaultPrincipalUserInfoJSONProviderTest {

    private DefaultPrincipalUserInfoJSONProvider principalUserInfoJSONProvider = new DefaultPrincipalUserInfoJSONProvider();


    @Test
    public void writeValue() {

        TestData data = new TestData();
        data.setProperty1("JUnit");
        data.setProperty2(123L);
        data.setProperty3(true);

        String value = principalUserInfoJSONProvider.writeValue(data);
        assertThat(value).isEqualTo("{\"property2\":123,\"property1\":\"JUnit\",\"property3\":true}");
    }

    @Test
    public void readValue() {

        TestData data = principalUserInfoJSONProvider.readValue("{\"property2\":123,\"property1\":\"JUnit\",\"property3\":true}", TestData.class);
        assertThat(data.getProperty1()).isEqualTo("JUnit");
        assertThat(data.getProperty2()).isEqualTo(123L);
        assertThat(data.isProperty3()).isEqualTo(Boolean.TRUE);
    }


    public static class TestData {
        private String property1;
        private Long property2;
        private boolean property3;

        public String getProperty1() {
            return property1;
        }

        public void setProperty1(String property1) {
            this.property1 = property1;
        }

        public Long getProperty2() {
            return property2;
        }

        public void setProperty2(Long property2) {
            this.property2 = property2;
        }

        public boolean isProperty3() {
            return property3;
        }

        public void setProperty3(boolean property3) {
            this.property3 = property3;
        }
    }

}