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

import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.interceptor.AnnotationInfo;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.shiro.authz.Permission;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Named;
import javax.interceptor.InvocationContext;
import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Set;

/**
 *
 */
@Named
@ApplicationScoped
public class MyCheckAccessDecisionVoter extends AbstractGenericVoter {
    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {

        InvocationContext invocationContext = accessDecisionVoterContext.getSource();
        AnnotationInfo annotationInfo = (AnnotationInfo) invocationContext.getContextData().get(AnnotationInfo.class.getName());
        List<Annotation> annotations = annotationInfo.getAnnotation(MyCheck.class);
        if (annotations.isEmpty()) {
            throw new IllegalArgumentException("Annotation @MyCheck not found on method but this Voter is called because it as found?");
        }

        Annotation annotation = annotations.get(0);  // Always the first one. When there are multiple ones, the first one is the one on method level.

        // This is the permission the user corresponding to the contents of the  value member.
        List<Permission> permissions = accessDecisionVoterContext.getMetaDataFor(Permission.class.getName(), List.class);

        if (permissions.isEmpty()) {
            violations.add(newSecurityViolation("Subject has not the required permission"));
        } else {
            SpecialNamedPermission specialNamedPermission = (SpecialNamedPermission) permissions.get(0);
            MyCheck myCheck = (MyCheck) annotation;
            if (specialNamedPermission.getMyCheckInfo() != MyCheckInfo.EXTENDED && specialNamedPermission.getMyCheckInfo() != myCheck.info()) {
                violations.add(newSecurityViolation("Subject has infotype BASIC but method required EXTENDED"));

            }
            if (violations.isEmpty()) {
                if (specialNamedPermission.getMyCheckInfo() != MyCheckInfo.EXTENDED) {
                    // Ok user has not the extended flag => meaning that it can call the method regardless of the parameter value.
                    // So now we have to check if the user has the value in the permission.
                    checkMethodHasParameterTypes(violations, invocationContext, Long.class);
                    if (violations.isEmpty()) {
                        // Ok we have a parameter of type Long

                        Long parameter = methodParameterCheckUtil.getAssignableParameter(invocationContext, Long.class);
                        if (!specialNamedPermission.getPartitions().contains(parameter)) {
                            violations.add(newSecurityViolation("Subject has not the permission to execute the method with the parameter value"));
                        }

                    }
                }
            }

        }
    }
}