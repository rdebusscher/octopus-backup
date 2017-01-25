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
package be.c4j.demo.security;

import be.c4j.ee.security.model.UserPrincipal;

import javax.annotation.PostConstruct;
import javax.enterprise.inject.Model;
import javax.inject.Inject;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@Model
public class InfoBean {

    @Inject
    private UserPrincipal userPrincipal;

    private List<Serializable> keys;

    @PostConstruct
    public void init() {
        keys = new ArrayList<Serializable>(userPrincipal.getInfo().keySet());
    }

    public String getInfoValue(String key) {
        Object info = userPrincipal.getUserInfo(key);
        return info == null ? "" : info.toString();
    }

    public List<Serializable> getKeys() {
        return keys;
    }
}
