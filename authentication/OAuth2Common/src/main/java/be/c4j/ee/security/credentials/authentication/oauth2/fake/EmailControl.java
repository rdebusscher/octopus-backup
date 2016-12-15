/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.credentials.authentication.oauth2.fake;

import javax.enterprise.context.ApplicationScoped;
import java.util.regex.Pattern;

/**
 *
 */
@ApplicationScoped
public class EmailControl {

    private static final String EMAIL_PATTERN =
            "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
                    + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

    public boolean isValidEmail(String email) {
        return email != null && Pattern.matches(EMAIL_PATTERN, email);
    }

    public String getDomain(String email) {
        String result = null;
        if (email != null) {
            String[] emailParts = email.split("@");

            if (emailParts.length == 2) {
                result = emailParts[1];
            }
        }
        return result;
    }

    /**
     * Assumes a valid email. So not null and contains @ sign.
     *
     * @param email
     * @return
     */
    public String[] getLocalParts(String email) {
        String[] emailParts = email.split("@");
        String[] split = emailParts[0].split("\\.");

        String[] result = new String[2];
        result[0] = capitalizeFirstLetter(split[0]);

        if (split.length > 1) {
            result[1] = capitalizeFirstLetter(split[1]);
        } else {
            result[1] = "??";
        }
        return result;
    }

    private String capitalizeFirstLetter(String value) {
        return value.substring(0, 1).toUpperCase() + value.substring(1);
    }

}
