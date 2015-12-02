/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.view.component.secured;

import javax.faces.component.UIComponent;
import java.util.List;

/**
 *
 */
public class SecuredComponentData {

    private final String[] voters;

    private final boolean not;

    private final boolean combined;

    private final SecuredComponentDataParameter[] parameters;

    private final String targets;

    private UIComponent targetComponent;

    private List<UIComponent> allTargetComponents;

    /**
     * Required for restoring the state
     */
    public SecuredComponentData() {
        this("", false, false, null, null);
    }

    public SecuredComponentData(final String someVoter, final boolean someNot, final boolean someCombined,
                                final SecuredComponentDataParameter[] someParameters, final String someTargets) {
        voters = someVoter.split(",");
        not = someNot;
        combined = someCombined;
        parameters = someParameters;
        targets = someTargets;
    }

    public SecuredComponentData(final SecuredComponentData securedComponentData) {
        voters = securedComponentData.getVoters();
        not = securedComponentData.isNot();
        combined = securedComponentData.isCombined();
        parameters = securedComponentData.getParameters();
        targets = securedComponentData.getTargets();
    }

    public void setTargetComponent(UIComponent someTargetComponent) {
        targetComponent = someTargetComponent;
    }

    public UIComponent getTargetComponent() {
        return targetComponent;
    }

    public List<UIComponent> getAllTargetComponents() {
        return allTargetComponents;
    }

    public void setAllTargetComponents(List<UIComponent> allTargetComponents) {
        this.allTargetComponents = allTargetComponents;
        if (!allTargetComponents.isEmpty()) {
            setTargetComponent(allTargetComponents.get(0));
        }
    }

    public String getTargets() {
        return targets;
    }

    public String[] getVoters() {
        return voters;
    }

    public boolean isNot() {
        return not;
    }

    public boolean isCombined() {
        return combined;
    }

    public SecuredComponentDataParameter[] getParameters() {
        return parameters;
    }

    public boolean hasAtRuntimeParameter() {
        boolean result = false;
        for (SecuredComponentDataParameter parameter : parameters) {
            if (parameter.isAtRuntime()) {
                result = true;
                break;
            }
        }
        return result;
    }
}
