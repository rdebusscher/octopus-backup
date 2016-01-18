package be.c4j.demo.security.exception.handler;

import be.c4j.ee.security.messages.FacesMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.faces.context.ExceptionHandler;
import javax.faces.context.ExceptionHandlerWrapper;
import javax.faces.event.ExceptionQueuedEvent;
import javax.faces.event.ExceptionQueuedEventContext;
import java.util.Iterator;

/**
 *
 */
public class GenericJSFExceptionHandler extends ExceptionHandlerWrapper {

    private static final Logger LOGGER = LoggerFactory.getLogger(GenericJSFExceptionHandler.class);

    private ExceptionHandler wrapped;

    GenericJSFExceptionHandler(ExceptionHandler wrapped) {
        this.wrapped = wrapped;
    }

    @Override
    public ExceptionHandler getWrapped() {
        return wrapped;
    }

    @Override
    public void handle() {

        handleBusinessException();
        //parent handle
        getWrapped().handle();
    }

    private void handleBusinessException() {
        Iterator<ExceptionQueuedEvent> i = getUnhandledExceptionQueuedEvents().iterator();
        while (i.hasNext()) {
            ExceptionQueuedEvent event = i.next();
            ExceptionQueuedEventContext context = (ExceptionQueuedEventContext) event.getSource();

            // get the exception from context
            Throwable t = context.getException();

            showMessage(t.getMessage());

            i.remove();  //exception is handled and won't result in an 500.
        }

    }


    private void showMessage(String msg) {

        FacesMessages messages = FacesMessages.getInstance();
        messages.text(msg).asError().show();
    }


}
