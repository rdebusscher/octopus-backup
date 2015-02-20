package be.c4j.ee.security.messages;

import org.apache.deltaspike.core.api.message.MessageContext;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.core.util.StringUtils;

import javax.enterprise.context.Dependent;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import java.io.Serializable;

/**
 *
 */
@Dependent
public class FacesMessages {

    private String template;
    private String text;
    private Serializable[] arguments;
    private String clientId;
    private FacesMessage.Severity severity;

    @Inject
    private MessageContext messageContext;

    public FacesMessages template(String template) {
        this.template = template;
        return this;
    }

    public FacesMessages withArguments(Serializable... arguments) {
        this.arguments = arguments;
        return this;
    }

    public FacesMessages text(String text) {
        this.text = text;
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

    public FacesMessages asInfo() {
        severity = FacesMessage.SEVERITY_INFO;
        return this;
    }

    public FacesMessages asWarn() {
        severity = FacesMessage.SEVERITY_WARN;
        return this;
    }

    public FacesMessages as(FacesMessage.Severity severity) {
        this.severity = severity;
        return this;
    }

    private FacesMessage.Severity determineSeverity(String key) {
        FacesMessage.Severity result = FacesMessage.SEVERITY_INFO;
        String[] parts = key.substring(1).split("\\.");
        result = checkSeverity(result, parts[0], "error", FacesMessage.SEVERITY_ERROR);
        result = checkSeverity(result, parts[0], "warn", FacesMessage.SEVERITY_WARN);
        result = checkSeverity(result, parts[0], "fatal", FacesMessage.SEVERITY_FATAL);
        return result;
    }

    private FacesMessage.Severity checkSeverity(FacesMessage.Severity result, String part, String severityText, FacesMessage.Severity severity) {
        if (severityText.equalsIgnoreCase(part)) {
            result = severity;
        }
        return result;
    }

    public void show() {
        FacesContext instance = FacesContext.getCurrentInstance();

        String msg;
        if (StringUtils.isEmpty(template)) {
            msg = text;
        } else {
            msg = messageContext.message().template(template).argument(arguments).toString();

            if (severity == null) {
               severity = determineSeverity(template);
            }
        }
        instance.addMessage(clientId, new FacesMessage(severity, msg, msg));
    }

    public String text() {
        return messageContext.message().template(template).argument(arguments).toString();
    }

    public static FacesMessages getInstance() {
        return BeanProvider.getContextualReference(FacesMessages.class);
    }
}
