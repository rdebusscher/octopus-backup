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
package be.c4j.demo.boundary;

import be.c4j.demo.security.custom.MyCheck;
import be.c4j.demo.security.custom.MyCheckInfo;

import javax.ejb.Stateless;

/**
 *
 */
@Stateless
public class ConceptByPartitionBoundary {

    @MyCheck(value = "demo")
    public String readByPartition(Long partitionId) {
        return String.format("Result value of default readBy for partition %s", partitionId);
    }

    @MyCheck(value = "demo", info = MyCheckInfo.EXTENDED)
    public String readByPartitionExtended(Long partitionId) {
        return String.format("Result value of extended readBy for partition %s", partitionId);
    }
}
