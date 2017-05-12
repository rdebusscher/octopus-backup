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

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 *
 */
@ApplicationScoped
public class MappingSystemAccountToApiKey {

    @Inject
    private SCSConfig SCSConfig;

    private Map<String, List<String>> systemAccountsMapping;

    @PostConstruct
    public void init() {
        systemAccountsMapping = new HashMap<String, List<String>>();

        String accountsMapFile = SCSConfig.getSystemAccountsMapFile();
        if (accountsMapFile == null || accountsMapFile.trim().isEmpty()) {
            throw new OctopusConfigurationException("A value for the parameter jwt.systemaccounts.map is required");
        }
        // FIXME Duplicated in JWTHelper !!
        InputStream inputStream = MappingSystemAccountToApiKey.class.getClassLoader().getResourceAsStream(accountsMapFile);
        try {
            if (inputStream == null) {
                inputStream = new FileInputStream(accountsMapFile);
            }

            Properties properties = new Properties();
            properties.load(inputStream);

            // key = api-key
            // value = list of system accounts
            String systemAccounts;
            for (String key : properties.stringPropertyNames()) {
                systemAccounts = properties.getProperty(key);
                systemAccountsMapping.put(key, Arrays.asList(systemAccounts.split(",")));
            }
        } catch (IOException e) {
            throw new OctopusConfigurationException(e.getMessage());
        }

        try {
            inputStream.close();
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }
    }

    public boolean containsOnlyOneMapping() {
        boolean result = systemAccountsMapping.size() == 1;
        if (result) {
            String onlyKey = systemAccountsMapping.keySet().iterator().next();
            result = systemAccountsMapping.get(onlyKey).size() == 1;
        }
        return result;
    }

    /**
     * execute the containsOnlyOneMapping() method first to verify there is only one !!
     *
     * @return
     */
    public String getOnlyAccount() {
        return systemAccountsMapping.values().iterator().next().get(0);
    }

    public String getApiKey(String systemAccount) {
        String result = null;
        for (Map.Entry<String, List<String>> entry : systemAccountsMapping.entrySet()) {
            if (entry.getValue().contains(systemAccount)) {
                result = entry.getKey();
            }
        }
        return result;
    }

    public List<String> getAccountList(String apiKey) {
        return systemAccountsMapping.get(apiKey);
    }
}
