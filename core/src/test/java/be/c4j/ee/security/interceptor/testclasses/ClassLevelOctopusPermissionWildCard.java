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
package be.c4j.ee.security.interceptor.testclasses;

import be.c4j.ee.security.interceptor.CallFeedbackCollector;
import be.c4j.ee.security.realm.OctopusPermissions;

/**
 *
 */
@OctopusPermissions("permission:1:*")
public class ClassLevelOctopusPermissionWildCard {

    public static final String CLASS_LEVEL_OCTOPUS_PERMISSION = "ClassLevel#octopusPermissionWildCard";


    public void octopusPermission1() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_OCTOPUS_PERMISSION);
    }

    public void octopusPermission1Bis() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_OCTOPUS_PERMISSION);
    }

}