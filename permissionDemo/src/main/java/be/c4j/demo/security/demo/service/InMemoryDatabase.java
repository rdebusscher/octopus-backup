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

import be.c4j.demo.security.demo.model.Department;
import be.c4j.demo.security.demo.model.Employee;
import be.c4j.demo.security.demo.model.HRAppPermission;
import be.c4j.demo.security.demo.model.Principal;
import be.c4j.demo.security.demo.model.dto.UserWithPermission;

import javax.annotation.PostConstruct;
import javax.annotation.security.PermitAll;
import javax.ejb.*;
import java.io.Serializable;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 *
 */
@Singleton
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.CONTAINER)
@Lock(LockType.WRITE)
@PermitAll
public class InMemoryDatabase {

    private Map<Long, Employee> employees;
    private Map<Long, Department> departments;
    private Map<String, Principal> principals;
    private Map<Serializable, Principal> principalsByUUID;

    private DateFormat fmt = new SimpleDateFormat("dd/MM/yyyy");

    /* Initialization of 'database' */

    @PostConstruct
    public void initializeDatabase() {
        initializeDepartments();
        initializeEmployees();
        setDepartmentManagers();
        setEmployeeManagers();

        initializePrincipals();
        initializePermissions();
    }

    private void initializeDepartments() {
        departments = new HashMap<Long, Department>();
        addDepartment(60L, "IT");
        addDepartment(90L, "Executive");
        addDepartment(100L, "Finance");
    }

    private void addDepartment(Long id, String name) {
        Department department = new Department();
        department.setId(id);
        department.setName(name);
        departments.put(id, department);
    }

    private void initializeEmployees() {
        employees = new HashMap<Long, Employee>();
        try {
            addEmployee(100L, "Steven King", "17/06/03", 24000, 90L);
            addEmployee(101L, "Neena Kochhar", "21/09/05", 17000, 90L);
            addEmployee(102L, "Lex De Haan", "13/01/01", 17000, 90L);
            addEmployee(103L, "Alexander Hunold", "03/01/06", 9000, 60L);
            addEmployee(104L, "Bruce Ernst", "21/05/07", 6000, 60L);
            addEmployee(105L, "David Austin", "25/06/05", 4800, 60L);
            addEmployee(106L, "Valli Pataballa", "05/02/06", 4800, 60L);
            addEmployee(107L, "Diana Lorentz", "07/02/07", 4200, 60L);
            addEmployee(108L, "Nancy Greenberg", "17/08/02", 12008, 100L);
            addEmployee(109L, "Daniel Faviet", "6/08/02", 9000, 100L);
            addEmployee(110L, "John Chen", "28/09/05", 8200, 100L);
            addEmployee(111L, "Ismael Sciarra", "30/09/05", 7700, 100L);
            addEmployee(112L, "Jose Manuel Urman", "07/03/06", 7800, 100L);
            addEmployee(113L, "Luis Popp", "07/12/07", 6900, 100L);
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    private void addEmployee(Long id, String name, String hireDate, double salary, Long departmentId) throws ParseException {
        Employee employee = new Employee();
        employee.setId(id);
        employee.setName(name);
        employee.setHireDate(fmt.parse(hireDate));
        employee.setSalary(salary);
        employee.setDepartment(departments.get(departmentId));
        employees.put(id, employee);
    }

    private void setDepartmentManagers() {
        setAsDepartmentManager(100L, 90L);
        setAsDepartmentManager(108L, 100L);
        setAsDepartmentManager(103L, 60L);
    }

    private void setAsDepartmentManager(Long managerId, Long departmentId) {
        departments.get(departmentId).setManager(employees.get(managerId));
    }

    private void setEmployeeManagers() {
        setEmployeeManager(101L, 100L);
        setEmployeeManager(102L, 100L);
        setEmployeeManager(103L, 102L);
        setEmployeeManager(104L, 103L);
        setEmployeeManager(105L, 103L);
        setEmployeeManager(106L, 103L);
        setEmployeeManager(107L, 103L);
        setEmployeeManager(108L, 101L);
        setEmployeeManager(109L, 108L);
        setEmployeeManager(110L, 108L);
        setEmployeeManager(111L, 108L);
        setEmployeeManager(112L, 108L);
        setEmployeeManager(113L, 108L);
    }

    private void setEmployeeManager(Long employeeId, Long managerId) {
        employees.get(employeeId).setManager(employees.get(managerId));
    }

    public void initializePrincipals() {
        principals = new HashMap<String, Principal>();
        principalsByUUID = new HashMap<Serializable, Principal>();

        addPrincipal(100L, "SKING", "GNIKS");
        addPrincipal(101L, "NKOCHHAR", "RAHHCOKN");
        addPrincipal(102L, "LDEHAAN", "NAAHEDL");
        addPrincipal(103L, "AHUNOLD", "DLONUHA");
        addPrincipal(104L, "BERNST", "TSNREB");
        addPrincipal(105L, "DAUSTIN", "NITSUAD");
        addPrincipal(106L, "VPATABAL", "LABATAPV");
        addPrincipal(107L, "DLORENTZ", "ZTNEROLD");
        addPrincipal(108L, "NGREENBE", "EBNEERGN");
        addPrincipal(109L, "DFAVIET", "TEIVAFD");
        addPrincipal(110L, "JCHEN", "NEHCJ");
        addPrincipal(111L, "ISCIARRA", "ARRAICSI");
        addPrincipal(112L, "JMURMAN", "NAMRUMJ");
        addPrincipal(113L, "LPOPP", "PPOPL");
    }

    private void addPrincipal(Long employeeId, String userName, String password) {
        Principal principal = new Principal();
        principal.setUserName(userName);
        principal.setPassword(password);
        principal.setEmployee(employees.get(employeeId));

        principals.put(userName, principal);
        principalsByUUID.put(principal.getId(), principal);
    }

    private void initializePermissions() {

        grantAll();
        grantDepartmentSalaryManager();
        grantDepartmentSalaryAll();
        grantEmployeeUpdateSalary();
        grantDepartmentCreate();
    }

    private void grantAll() {
        HRAppPermission permission = createPermissionAll();
        grantPermissions(permission, new Long[]{}, new Long[]{100L}, new Long[]{});
    }

    private void grantDepartmentSalaryAll() {
        HRAppPermission permission = createPermissionDepartmentSalaryAll();
        grantPermissions(permission, new Long[]{}, new Long[]{108L}, new Long[]{});
    }

    private void grantDepartmentSalaryManager() {
        HRAppPermission permission = createPermissionDepartmentSalaryManager();
        for (Department department : departments.values()) {
            Principal manager = findPrincipal(department.getManager());
            if (manager.getEmployee().getId() != 100) {

                manager.addPermission(permission);
            }
        }
    }

    private void grantEmployeeUpdateSalary() {
        HRAppPermission permission = createPermissionEmployeeUpdateSalary();
        grantPermissions(permission, new Long[]{}, new Long[]{101L, 102L, 103L, 108L}, new Long[]{});
    }

    private void grantDepartmentCreate() {
        HRAppPermission permission = createPermissionDepartmentCreate();
        grantPermissions(permission, new Long[]{}, new Long[]{108L}, new Long[]{});
    }

    private Principal findPrincipal(Employee manager) {
        Principal result = null;
        Iterator<Principal> principalIterator = principals.values().iterator();
        while (result == null && principalIterator.hasNext()) {
            Principal principal = principalIterator.next();
            if (manager.equals(principal.getEmployee())) {
                result = principal;
            }
        }
        return result;
    }

    private void grantPermissions(HRAppPermission permission, Long[] departments, Long[] employees, Long[] excludedEmployees) {
        List<Long> departmentList = Arrays.asList(departments);
        List<Long> employeeList = Arrays.asList(employees);
        List<Long> excludedEmployeeList = Arrays.asList(excludedEmployees);
        for (Principal principal : principals.values()) {
            if (matchedPrincipal(principal, departmentList, employeeList, excludedEmployeeList)) {
                principal.addPermission(permission);
            }
        }
    }

    private boolean matchedPrincipal(Principal principal, List<Long> departments, List<Long> employees, List<Long> excludedEmployees) {
        Long employeeId = principal.getEmployee().getId();
        return ((principal.getEmployee().getDepartment() != null && departments.contains(principal.getEmployee().getDepartment().getId())) ||
                employees.contains(employeeId)) && !excludedEmployees.contains(employeeId);

    }

    private HRAppPermission createPermissionAll() {
        return new HRAppPermission("ALL", "*", "*", "*");
    }


    private HRAppPermission createPermissionDepartmentSalaryAll() {
        return new HRAppPermission("DEPARTMENT_SALARY_ALL", "DEPARTMENT", "SALARY", "ALL");
    }

    private HRAppPermission createPermissionDepartmentSalaryManager() {
        return new HRAppPermission("DEPARTMENT_SALARY_MANAGER", "DEPARTMENT", "SALARY", "MANAGER");
    }

    private HRAppPermission createPermissionEmployeeReadAll() {
        return new HRAppPermission("EMPLOYEE_READ_ALL", "EMPLOYEE", "READ", "ALL");
    }

    private HRAppPermission createPermissionEmployeeUpdateSalary() {
        return new HRAppPermission("EMPLOYEE_UPDATE_SALARY", "EMPLOYEE", "UPDATE", "SALARY");
    }

    private HRAppPermission createPermissionDepartmentCreate() {
        return new HRAppPermission("DEPARTMENT_CREATE", "DEPARTMENT", "CREATE", "*");
    }

    /*  'Database' actions */

    @Lock(LockType.READ)
    public List<UserWithPermission> getAvailableUsersWithInfo() {
        if (principals == null) {
            // WLS12C. PostConstruct method isn't called in our case.
            // And constructor isn't working since WLS is complaining about invoking local methods.
            initializeDatabase();
        }
        List<UserWithPermission> result = new ArrayList<UserWithPermission>();
        for (Principal principal : principals.values()) {
            String permissionInfo = getPermissionInfo(principal);
            result.add(new UserWithPermission(principal.getUserName(), principal.getEmployee().getName(), permissionInfo));
        }
        return result;
    }

    private String getPermissionInfo(Principal principal) {
        Collection<HRAppPermission> permissions = getPermissions(principal.getId());
        StringBuilder result = new StringBuilder();
        for (HRAppPermission permission : permissions) {
            if (result.length() > 0) {
                result.append(" - ");
            }
            result.append(permission.getDomainPermissionRepresentation());
        }
        return result.toString();
    }

    @Lock(LockType.READ)
    public Principal getPrincipalByUserName(String userName) {
        return principals.get(userName);
    }

    @Lock(LockType.READ)
    public Collection<Department> getDepartmentList() {
        return departments.values();
    }

    @Lock(LockType.READ)
    public List<HRAppPermission> getPermissionList() {
        List<HRAppPermission> result = new ArrayList<HRAppPermission>();
        result.add(createPermissionAll());
        result.add(createPermissionDepartmentSalaryManager());
        result.add(createPermissionDepartmentSalaryAll());
        result.add(createPermissionEmployeeReadAll());
        result.add(createPermissionEmployeeUpdateSalary());
        result.add(createPermissionDepartmentCreate());
        return result;
    }

    @Lock(LockType.READ)
    public Collection<HRAppPermission> getPermissions(Serializable id) {
        return principalsByUUID.get(id).getPermissions();
    }

    @Lock(LockType.READ)
    public Employee findEmployeeByPrincipal(Serializable id) {
        return principalsByUUID.get(id).getEmployee();
    }

    @Lock(LockType.READ)
    public List<Employee> getEmployeeListForDepartment(Long departmentId) {
        List<Employee> result = new ArrayList<Employee>();
        for (Employee employee : employees.values()) {
            if (departmentId.equals(employee.getDepartment().getId())) {
                result.add(employee);
            }
        }
        return result;
    }

    public Employee findEmployeeById(Long employeeId) {
        Employee result = employees.get(employeeId);
        // We need to clone because otherwise changes made in the screen are directly propagated to the 'DB'
        return cloneEmployee(result);
    }

    private Employee cloneEmployee(Employee data) {
        Employee result = new Employee();
        result.setId(data.getId());
        result.setName(data.getName());
        result.setManager(data.getManager());
        result.setSalary(data.getSalary());
        result.setDepartment(cloneDepartment(data.getDepartment()));

        return result;
    }

    private Department cloneDepartment(Department data) {
        Department result = new Department();
        result.setId(data.getId());
        result.setName(data.getName());
        //result.setManager(cloneEmployee(data.getManager()));
        return result;
    }

    public Long getManagerIdOfEmployee(Long employeeId) {
        Long result = null;
        Employee employee = employees.get(employeeId);
        if (employee != null && employee.getManager() != null) {
            result = employee.getManager().getId();
        }
        return result;
    }

    public Employee getEmployee(Long employeeId) {
        return employees.get(employeeId);
    }

    public void updateEmployee(Employee employee) {
        employees.put(employee.getId(), employee);
    }

    public Department getDepartmentByName(String departmentName) {
        Department result = null;
        String basicName = departmentName.trim().toLowerCase();
        for (Department department  : departments.values()) {
            if (department.getName().toLowerCase().equals(basicName)) {
                result = department;
                break;
            }
        }
        return result;
    }

    public void createDepartment(Department department) {
        department.setId((long) (departments.size()+1));
        departments.put(department.getId(), department);
    }
}
