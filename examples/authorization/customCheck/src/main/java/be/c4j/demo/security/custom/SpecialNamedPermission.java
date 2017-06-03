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
package be.c4j.demo.security.custom;

import be.c4j.ee.security.permission.NamedDomainPermission;

import java.util.Collections;
import java.util.List;

/**
 * The Custom version of the Permission. Should be immutable so that permission can't be altered once it is created.
 */

public class SpecialNamedPermission extends NamedDomainPermission {

    private MyCheckInfo myCheckInfo;
    private List<Long> partitions;

    public SpecialNamedPermission(String someName, String wildcardString, MyCheckInfo myCheckInfo, List<Long> partitions) {
        super(someName, wildcardString);
        this.myCheckInfo = myCheckInfo;
        if (partitions != null) {
            this.partitions = Collections.unmodifiableList(partitions);  // Security mesure, make it unmodifiable so that a CustomerVoter for example can't change it.
        } else {
            this.partitions = Collections.unmodifiableList(Collections.EMPTY_LIST);  // Security mesure, make it unmodifiable so that a CustomerVoter for example can't change it.

        }
    }

    public MyCheckInfo getMyCheckInfo() {
        return myCheckInfo;
    }

    public List<Long> getPartitions() {
        return partitions;
    }
}
