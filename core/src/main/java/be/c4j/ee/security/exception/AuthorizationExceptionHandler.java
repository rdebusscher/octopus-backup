package be.c4j.ee.security.exception;

import org.apache.shiro.authz.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.faces.FacesException;
import javax.faces.application.FacesMessage;
import javax.faces.application.NavigationHandler;
import javax.faces.context.ExceptionHandler;
import javax.faces.context.ExceptionHandlerWrapper;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.event.ExceptionQueuedEvent;
import javax.faces.event.ExceptionQueuedEventContext;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

public class AuthorizationExceptionHandler extends ExceptionHandlerWrapper {
    private static final Logger log = LoggerFactory.getLogger(AuthorizationExceptionHandler.class.getCanonicalName());

    private ExceptionHandler wrapped;

    AuthorizationExceptionHandler(ExceptionHandler exception) {
        this.wrapped = exception;
    }

    @Override
    public ExceptionHandler getWrapped() {
        return wrapped;
    }

    @Override
    public void handle() throws FacesException {

        Iterator<ExceptionQueuedEvent> i = getUnhandledExceptionQueuedEvents().iterator();
        while (i.hasNext()) {
            ExceptionQueuedEvent event = i.next();
            ExceptionQueuedEventContext context = (ExceptionQueuedEventContext) event.getSource();

            // get the exception from context
            Throwable t = context.getException();

            FacesContext facesContext = FacesContext.getCurrentInstance();
            ExternalContext externalContext = facesContext.getExternalContext();
            Map<String, Object> requestMap = externalContext.getRequestMap();
            NavigationHandler nav = facesContext.getApplication().getNavigationHandler();

            Throwable unauthorized = getUnauthorizedException(t);
            //here you do what ever you want with exception
            if (unauthorized != null) {
                try {

                    //log error ?
                    log.error("Critical Exception!", t);

                    externalContext.getFlash().setKeepMessages(true);
                    facesContext.addMessage(null,
                            new FacesMessage(FacesMessage.SEVERITY_ERROR, unauthorized.getMessage(), unauthorized.getMessage()));

                    //redirect error page
                    requestMap.put("exceptionMessage", t.getMessage());
                    try {
                        externalContext.redirect(externalContext.getRequestContextPath() +"/unauthorized.xhtml");

                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    facesContext.renderResponse();


                } finally {
                    //remove it from queue
                    i.remove();
                }
            }
        }
        //parent handle
        getWrapped().handle();
    }

    private Throwable getUnauthorizedException(Throwable someException) {
        Throwable result = null;
        if (someException.getClass().getName().equals(UnauthorizedException.class.getName())) {
            result = someException;
        } else {
            if (someException.getCause() != null) {
                result = getUnauthorizedException(someException.getCause());
            }
        }
        return result;
    }

}