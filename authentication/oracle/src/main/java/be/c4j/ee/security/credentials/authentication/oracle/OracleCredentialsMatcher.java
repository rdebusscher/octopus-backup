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
package be.c4j.ee.security.credentials.authentication.oracle;

import be.rubus.web.jerry.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

/**
 *
 */
public class OracleCredentialsMatcher implements CredentialsMatcher {


    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        if (token instanceof UsernamePasswordToken) {
            OraclePasswordExecutor passwordExecutor = BeanProvider.getContextualReference(OraclePasswordExecutor.class);
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
            return passwordExecutor.checkPassword(usernamePasswordToken.getUsername(), String.valueOf(usernamePasswordToken.getPassword()));
        } else {
            // No logging required as we can have multiple matcher defined and another can handle it.
            return false;
        }
    }
}
