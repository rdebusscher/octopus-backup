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
