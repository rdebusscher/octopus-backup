package be.c4j.ee.security.messages;

import org.apache.deltaspike.core.api.message.MessageContext;

import javax.enterprise.context.Dependent;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;

/**
 *
 */
@Dependent
public class FacesMessages {

    private String template;
    private String clientId;
    private FacesMessage.Severity severity = FacesMessage.SEVERITY_INFO;

    @Inject
    private MessageContext messageContext;

    public FacesMessages template(String template) {
        this.template = template;
        return this;
    }

    public FacesMessages on(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public FacesMessages asError() {
        severity = FacesMessage.SEVERITY_ERROR;
        return this;
    }

    public void show() {
        FacesContext instance = FacesContext.getCurrentInstance();

        String msg = messageContext.message().template(template).toString();
        instance.addMessage(clientId, new FacesMessage(severity, msg, msg));
    }
}
