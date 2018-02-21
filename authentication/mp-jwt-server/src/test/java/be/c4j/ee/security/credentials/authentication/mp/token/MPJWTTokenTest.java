/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.c4j.ee.security.credentials.authentication.mp.token;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class MPJWTTokenTest {

    private static final String KEY = "key";
    private static final String VALUE = "value";

    @Test
    public void addAdditionalClaims() {
        MPJWTToken token = new MPJWTToken();

        assertThat(token.getAdditionalClaims()).isNull();

        token.addAdditionalClaims(KEY, VALUE);
        assertThat(token.getAdditionalClaims()).containsOnlyKeys(KEY);
        assertThat(token.getAdditionalClaims()).containsValues(VALUE);
    }

    @Test
    public void getAdditionalClaim() {
        MPJWTToken token = new MPJWTToken();

        token.addAdditionalClaims(KEY, VALUE);
        assertThat(token.getAdditionalClaim(KEY)).isEqualTo(VALUE);
        assertThat(token.getAdditionalClaim("something")).isNull();
    }

}