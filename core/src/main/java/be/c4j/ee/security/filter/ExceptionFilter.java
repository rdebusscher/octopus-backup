package be.c4j.ee.security.filter;

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 */

public class ExceptionFilter extends AdviceFilter {

    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Exception existing) throws ServletException, IOException {
        if (existing != null) {
            Throwable unexpectedException = getUnexpectedException(existing);
            if (unexpectedException != null) {
                OctopusUnexpectedException unexpected = (OctopusUnexpectedException) unexpectedException;
                Logger logger = LoggerFactory.getLogger(ExceptionFilter.class);
                logger.error(unexpected.getCause().getMessage(), unexpected.getCause());
                // Since we are in a finally block, this exception takes over and thus erasing all infomation we have about stacktraces
                // OWASP A6
                throw new OctopusUnexpectedException("Something went wrong");
            }
        }
        super.cleanup(request, response, existing);
    }

    private Throwable getUnexpectedException(Throwable exception) {
        if (exception instanceof OctopusUnexpectedException) {
            return exception;
        } else {
            return getUnexpectedException(exception.getCause());
        }
    }
}
