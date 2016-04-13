package be.c4j.demo.view;

import be.c4j.demo.DemoService;
import be.c4j.ee.security.context.OctopusSecurityContext;

import javax.enterprise.inject.Model;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;

/**
 *
 */
@Model
public class PageBean {

    @Inject
    private DemoService demoService;

    @Inject
    private OctopusSecurityContext octopusSecurityContext;

    private String text;
    private String textSystem;

    public void testAsync() {
        try {
            text = demoService.sayHello();
        } catch (Exception e) {
            handleException(e);
        }
    }

    public String getText() {
        return text;
    }

    public void testSystemAccount() {
        try {
            octopusSecurityContext.activateSystemAccount("Demo");
            textSystem = demoService.fromMachine();
        } catch (Exception e) {
            handleException(e);
        }
    }

    private void handleException(Exception e) {
        String msg = "Exception = " + e.getClass().getSimpleName() + " - message = " + e.getMessage();
        FacesContext facesContext = FacesContext.getCurrentInstance();
        facesContext.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, msg));

    }

    public String getTextSystem() {
        return textSystem;
    }
}
