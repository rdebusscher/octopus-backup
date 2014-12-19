package be.c4j.demo.security.demo.exception.handler;

import be.c4j.ee.security.messages.FacesMessages;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.ejb.EJBException;
import javax.faces.FacesException;
import javax.faces.context.ExceptionHandler;
import javax.faces.context.ExceptionHandlerWrapper;
import javax.faces.event.ExceptionQueuedEvent;
import javax.faces.event.ExceptionQueuedEventContext;
import java.util.Iterator;

/**
 *
 */
public class DemoExceptionHandler extends ExceptionHandlerWrapper {

    private ExceptionHandler wrapped;

    DemoExceptionHandler(ExceptionHandler wrapped) {
        this.wrapped = wrapped;
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

            Throwable businessException = getBusinessException(t);

            //here you do what ever you want with exception
            if (businessException != null) {
                try {
                    FacesMessages facesMessages = BeanProvider.getContextualReference(FacesMessages.class);

                    facesMessages.template(businessException.getMessage()).asError().show();

                } finally {
                    //remove it from queue
                    i.remove();
                }
            }
        }
        //parent handle
        getWrapped().handle();
    }

    private Throwable getBusinessException(Throwable exception) {
        Throwable result = null;
        if (exception != null && exception.getCause() instanceof EJBException) {
            result = ((EJBException) exception.getCause()).getCausedByException();
        }
        return result;
    }
}
