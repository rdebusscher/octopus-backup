/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
package be.c4j.demo.security.demo.view;

import be.c4j.demo.security.demo.model.Employee;
import be.c4j.demo.security.demo.service.EmployeeService;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.core.api.scope.ViewAccessScoped;


import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.Map;

/**
 *
 */
@Named
@ViewAccessScoped
public class EmployeeBean implements Serializable {

    @Inject
    private transient UserPrincipal principal;

    @Inject
    private transient EmployeeService employeeService;

    private Long employeeId;

    private Employee employee = new Employee();

    public Long getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(Long employeeId) {
        this.employeeId = employeeId;
    }

    private boolean youMarkerFound() {
        Map<String, String> requestParameterMap = FacesContext.getCurrentInstance().
                getExternalContext().getRequestParameterMap();
        return requestParameterMap.containsKey("you");
    }

    public void loadEmployee() {
        if (youMarkerFound()) {
            employeeId = null;
        }
        if (employeeId == null) {

            employee = employeeService.getEmployee(principal);
        } else {
            if (!employeeId.equals(employee.getId())) {
                employee = employeeService.getEmployee(employeeId);
            }
        }

    }

    public Employee getEmployee() {
        return employee;
    }

    public void setEmployee(Employee employee) {
        this.employee = employee;
    }

    public void saveSalary() {
        // employeeId is also filled by using f:param within p:commandButton.
        employee.setId(employeeId);
        employeeService.updateSalary(employee);
    }

    /*
     * Manual initialization is required after deserialization.  departmentService is not serializable
     * so this can solve the problem.
     */
    private void readObject(ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // FIXME principal =
        employeeService = BeanProvider.getContextualReference(EmployeeService.class);
    }

}
