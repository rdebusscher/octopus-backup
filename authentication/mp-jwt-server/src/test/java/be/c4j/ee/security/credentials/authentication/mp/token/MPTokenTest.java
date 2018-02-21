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
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

@RunWith(Parameterized.class)
public class MPTokenTest {

    private static final String USER_NAME = "userName";
    private static final String UPN = "upn";
    private static final String SUB = "sub";

    private String expected;
    private String preferredUserName;
    private String upn;
    private String sub;

    public MPTokenTest(String expected, String preferredUserName, String upn, String sub) {
        this.expected = expected;
        this.preferredUserName = preferredUserName;
        this.upn = upn;
        this.sub = sub;
    }

    @Parameterized.Parameters
    public static List<Object[]> defineScenarios() {
        return Arrays.asList(new Object[][]{
                {USER_NAME, USER_NAME, null, null},    //0
                {UPN, null, UPN, null},               //1
                {SUB, null, null, SUB},               //2
                {USER_NAME, USER_NAME, UPN, null},    //3
                {USER_NAME, USER_NAME, null, SUB},    //4
                {UPN, null, UPN, SUB},               //5

        });
    }

    @Test
    public void getPrincipal() {
        MPJWTToken mpjwtToken = new MPJWTToken();
        mpjwtToken.setPreferredUsername(preferredUserName);
        mpjwtToken.setUpn(upn);
        mpjwtToken.setSub(sub);
        MPToken token = new MPToken(mpjwtToken);
        assertThat(token.getPrincipal()).isEqualTo(expected);
    }

}