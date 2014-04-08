package be.c4j.demo.security.demo.service;

import be.c4j.demo.security.demo.exception.DuplicateDepartmentException;
import be.c4j.demo.security.demo.model.Department;
import be.c4j.demo.security.demo.model.Employee;
import be.c4j.demo.security.demo.model.dto.DepartmentWithSalaryTotal;
import be.c4j.demo.security.permission.DemoPermission;
import be.c4j.demo.security.permission.DemoPermissionCheck;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresUser;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 *
 */
@Stateless
@RequiresUser
public class DepartmentService {

    @EJB
    private InMemoryDatabase data;

    public List<DepartmentWithSalaryTotal> getAllDepartments() {
        Collection<Department> departmentList = data.getDepartmentList();
        List<DepartmentWithSalaryTotal> result = new ArrayList<DepartmentWithSalaryTotal>();
        for (Department department : departmentList) {
            List<Employee> employeeListForDepartment = data.getEmployeeListForDepartment(department.getId());
            result.add(new DepartmentWithSalaryTotal(department, calculateTotalSalary(employeeListForDepartment)));
        }
        return result;
    }

    private double calculateTotalSalary(List<Employee> employeeListForDepartment) {
        double result = 0.0;
        for (Employee employee : employeeListForDepartment) {
            result += employee.getSalary();
        }
        return result;
    }

    @DemoPermissionCheck(DemoPermission.DEPARTMENT_CREATE)
    public void createDepartment(String departmentName) {
        Department departmentByName = data.getDepartmentByName(departmentName);
        if (departmentByName != null) {
            throw new DuplicateDepartmentException();
        }
        Department department = new Department();
        department.setName(departmentName);
        data.createDepartment(department);
    }
}
