package be.c4j.demo.security.demo.view;

import be.c4j.demo.security.demo.model.Employee;
import be.c4j.demo.security.demo.service.EmployeeService;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.myfaces.extensions.cdi.core.api.scope.conversation.ViewAccessScoped;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;

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
        employeeService = CodiUtils.getContextualReferenceByClass(EmployeeService.class);
    }

}
