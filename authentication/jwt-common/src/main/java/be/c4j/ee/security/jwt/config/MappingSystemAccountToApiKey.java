/*
 * Copyright 2014-2018 Rudy De Busscher
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

import be.c4j.ee.security.systemaccount.SystemAccountMapReader;
import be.c4j.ee.security.util.StringUtil;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class MappingSystemAccountToApiKey {

    @Inject
    private JWTConfig jwtConfig;

    @Inject
    private SystemAccountMapReader systemAccountMapReader;

    @Inject
    private StringUtil stringUtil;

    private boolean systemAccountUsageActive;

    private Map<String, List<String>> systemAccountsMapping;

    @PostConstruct
    public void init() {
        systemAccountsMapping = new HashMap<String, List<String>>();

        String accountsMapFile = jwtConfig.getSystemAccountsMapFile();
        if (stringUtil.isEmpty(accountsMapFile)) {
            systemAccountUsageActive = false;
            return;
        }
        systemAccountUsageActive = true;

        systemAccountsMapping = systemAccountMapReader.readMap(accountsMapFile);
    }

    public boolean isSystemAccountUsageActive() {
        return systemAccountUsageActive;
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
