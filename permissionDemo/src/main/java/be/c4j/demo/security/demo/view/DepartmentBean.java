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
import be.c4j.demo.security.demo.model.dto.DepartmentWithSalaryTotal;
import be.c4j.demo.security.demo.service.DepartmentService;
import be.c4j.demo.security.demo.service.EmployeeService;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.core.api.scope.ViewAccessScoped;


import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.List;

/**
 *
 */
@ViewAccessScoped
@Named
public class DepartmentBean implements Serializable {

    @Inject
    private transient DepartmentService departmentService;

    @Inject
    private transient EmployeeService employeeService;

    private List<DepartmentWithSalaryTotal> allDepartments;

    private Long departmentId;
    private List<Employee> employeesOfDepartment;

    public List<DepartmentWithSalaryTotal> getAllDepartments() {
        if (allDepartments == null) {
            allDepartments = departmentService.getAllDepartments();
        }
        return allDepartments;
    }

    public Long getDepartmentId() {
        return departmentId;
    }

    public void setDepartmentId(Long departmentId) {
        this.departmentId = departmentId;
    }

    public List<Employee> getEmployeesOfDepartment() {
        return employeesOfDepartment;
    }

    public void loadEmployees() {
        employeesOfDepartment = employeeService.getEmployeesOfDepartment(departmentId);
    }

    /*
         * Manual initialization is required after deserialization.  departmentService is not serializable
         * so this can solve the problem.
         */
    private void readObject(ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        departmentService = BeanProvider.getContextualReference(DepartmentService.class);
        employeeService = BeanProvider.getContextualReference(EmployeeService.class);
    }
}
