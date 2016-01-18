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
package be.c4j.demo.security.demo.service;

import be.c4j.demo.security.demo.exception.EmployeeLowerSalaryException;
import be.c4j.demo.security.demo.model.Employee;
import be.c4j.demo.security.demo.security.EmployeeInfoVoter;
import be.c4j.demo.security.demo.security.EmployeeSalaryUpdateVoter;
import be.c4j.ee.security.custom.CustomVoterCheck;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authz.annotation.RequiresUser;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import java.util.List;

/**
 *
 */
@Stateless
public class EmployeeService {

    @EJB
    private InMemoryDatabase data;

    @CustomVoterCheck(EmployeeInfoVoter.class)
    public Employee getEmployee(UserPrincipal principal) {
        return data.findEmployeeByPrincipal(principal.getId());
    }

    @CustomVoterCheck(EmployeeInfoVoter.class)
    public Employee getEmployee(Long employeeId) {
        return data.findEmployeeById(employeeId);
    }

    @RequiresUser
    public List<Employee> getEmployeesOfDepartment(Long departmentId) {
        return data.getEmployeeListForDepartment(departmentId);
    }

    @RequiresUser
    public Long getManagerIdOfEmployee(Long employeeId) {
        return data.getManagerIdOfEmployee(employeeId);
    }


    @CustomVoterCheck(EmployeeSalaryUpdateVoter.class)
    public void updateSalary(Employee employee) {
        Employee dataEmployee = data.getEmployee(employee.getId());
        if (dataEmployee.getSalary() > employee.getSalary()) {
           throw new EmployeeLowerSalaryException();
        }
        dataEmployee.setSalary(employee.getSalary());
        data.updateEmployee(dataEmployee);
    }
}
