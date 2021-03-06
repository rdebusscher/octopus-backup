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

import be.c4j.ee.security.custom.CustomVoterCheck;
import be.c4j.ee.security.interceptor.CallFeedbackCollector;
import be.c4j.ee.security.realm.OctopusPermissions;
import be.c4j.ee.security.realm.OctopusRoles;
import be.c4j.ee.security.realm.OnlyDuringAuthentication;
import be.c4j.ee.security.realm.OnlyDuringAuthorization;
import be.c4j.ee.security.systemaccount.SystemAccount;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresUser;

import javax.annotation.security.PermitAll;

/**
 *
 */
@PermitAll
public class MethodLevelOverride {

    public static final String METHOD_LEVEL_NO_ANNOTATION = "MethodLevelOverride#noAnnotation";
    public static final String METHOD_LEVEL_REQUIRES_USER = "MethodLevelOverride#requiresUser";
    public static final String METHOD_LEVEL_IN_AUTHENTICATION = "MethodLevelOverride#inAuthentication";
    public static final String METHOD_LEVEL_IN_AUTHORIZATION = "MethodLevelOverride#inAuthorization";
    public static final String METHOD_LEVEL_PERMISSION1 = "MethodLevelOverride#permission1";
    public static final String METHOD_LEVEL_PERMISSION2 = "MethodLevelOverride#permission2";
    public static final String METHOD_LEVEL_CUSTOM_VOTER = "MethodLevelOverride#customVoter";
    public static final String METHOD_LEVEL_REQUIRES_PERMISSION1 = "MethodLevelOverride#requiresPermission1";
    public static final String METHOD_LEVEL_REQUIRES_PERMISSION2 = "MethodLevelOverride#requiresPermission2";
    public static final String METHOD_LEVEL_SYSTEM_ACCOUNT1 = "MethodLevel#systemAccount1";
    public static final String METHOD_LEVEL_OCTOPUS_PERMISSION1 = "MethodLevel#octopusPermission1";
    public static final String METHOD_LEVEL_OCTOPUS_PERMISSION2 = "MethodLevel#octopusPermission2";
    public static final String METHOD_LEVEL_OCTOPUS_ROLE = "MethodLevel#octopusRole";

    public void noAnnotation() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_NO_ANNOTATION);
    }

    @RequiresUser
    public void requiresUser() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_REQUIRES_USER);
    }

    @OnlyDuringAuthentication
    public void inAuthentication() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_IN_AUTHENTICATION);
    }

    @OnlyDuringAuthorization
    public void inAuthorization() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_IN_AUTHORIZATION);
    }

    @TestPermissionCheck(TestPermission.PERMISSION1)
    public void permission1() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_PERMISSION1);
    }

    @TestPermissionCheck(TestPermission.PERMISSION2)
    public void permission2() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_PERMISSION2);
    }

    @CustomVoterCheck(TestCustomVoter.class)
    public void customVoter() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_CUSTOM_VOTER);
    }

    @RequiresPermissions("shiro1:*:*")
    public void requiresPermission1() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_REQUIRES_PERMISSION1);
    }

    @RequiresPermissions("shiro2:*:*")
    public void requiresPermission2() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_REQUIRES_PERMISSION2);
    }

    @SystemAccount("account1")
    public void systemAccountValue1() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_SYSTEM_ACCOUNT1);
    }

    @OctopusPermissions("permissionName")
    public void octopusPermission1() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_OCTOPUS_PERMISSION1);
    }

    @OctopusPermissions("octopus:action:*")
    public void octopusPermission2() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_OCTOPUS_PERMISSION2);
    }

    @OctopusRoles("role1")
    public void octopusRole() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_OCTOPUS_ROLE);
    }

}
