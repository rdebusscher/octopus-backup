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
package be.c4j.ee.security.sso.encryption;

import java.io.Serializable;

/**
 * Used by the SSO Client / Server parts to encrypt (with JWT for example) the applicationName.
 * And thus an additional protection for unauthorized usage of the SSO facilities of Octopus.
 * TODO Review usage now that we have complete openId support
 */
public interface SSODataEncryptionHandler extends Serializable {

    String encryptData(String data, String apiKey);

    String decryptData(String encryptedData, String apiKey);

    boolean requiresApiKey();

    boolean validate(String apiKey, String token);
}
