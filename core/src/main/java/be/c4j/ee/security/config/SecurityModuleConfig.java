/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package be.c4j.ee.security.config;

import be.c4j.ee.security.permission.NamedPermission;
import org.apache.myfaces.extensions.cdi.core.api.config.AbstractAttributeAware;
import org.apache.myfaces.extensions.cdi.core.api.config.CodiConfig;
import org.apache.myfaces.extensions.cdi.core.api.config.ConfigEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.util.Properties;

@ApplicationScoped
public class SecurityModuleConfig extends AbstractAttributeAware implements CodiConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityModuleConfig.class);

    private Properties configProperties;

    private Class<? extends Annotation> namedPermissionCheckClass;

    private Class<? extends NamedPermission> namedPermissionClass;

    protected SecurityModuleConfig() {

    }

    @PostConstruct
    public void init() {
        configProperties = new Properties();
        try {
            InputStream resourceStream = SecurityModuleConfig.class.getClassLoader()
                                                                   .getResourceAsStream("securityModuleConfig.properties");
            if (resourceStream != null) {
                configProperties.load(resourceStream);
            }
        } catch (IOException e) {
            ;
        }

    }

    @ConfigEntry
    public String getLocationSecuredURLProperties() {
        return configProperties.getProperty("securedURLs.file", "/WEB-INF/securedURLs.ini");
    }

    @ConfigEntry
    public String getNamedPermission() {
        return configProperties.getProperty("namedPermission", null);
    }

    @ConfigEntry
    public String getNamedPermissionCheck() {
        return configProperties.getProperty("namedPermissionCheck", null);
    }

    public Class<? extends Annotation> getNamedPermissionCheckClass() {
        if (namedPermissionCheckClass == null) {

            try {
                namedPermissionCheckClass = (Class<? extends Annotation>) Class.forName(getNamedPermissionCheck());
            } catch (ClassNotFoundException e) {
                LOGGER.error("Class defined in configuration property namedPermissionCheck is not found", e);
            }
        }
        return namedPermissionCheckClass;
    }

    public Class<? extends NamedPermission> getNamedPermissionClass() {
        if (namedPermissionClass == null) {

            try {
                namedPermissionClass = (Class<? extends NamedPermission>) Class.forName(getNamedPermission());
            } catch (ClassNotFoundException e) {
                LOGGER.error("Class defined in configuration property namedPermissionCheck is not found", e);
            }
        }
        return namedPermissionClass;
    }


}
