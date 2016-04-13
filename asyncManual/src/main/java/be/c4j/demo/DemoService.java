package be.c4j.demo;

import be.c4j.ee.security.context.OctopusSecurityContext;
import be.c4j.ee.security.systemaccount.SystemAccount;

import javax.annotation.security.PermitAll;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.inject.Inject;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 *
 */
@Stateless
@PermitAll
public class DemoService {

    @Inject
    private WorkerService workerService;

    @Inject
    private OctopusSecurityContext octopusSecurityContext;

    public String sayHello() throws Exception {
        octopusSecurityContext.prepareForAsyncUsage();

        Future<String> stringFuture = workerService.doInBackground(octopusSecurityContext);
        String result = null;
        try {
            result = stringFuture.get(500L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            if (e.getCause() instanceof EJBException) {
                throw ((EJBException) e.getCause()).getCausedByException();
            }
            e.printStackTrace();
        } catch (TimeoutException e) {
            e.printStackTrace();
        }
        return result;
    }

    @SystemAccount("Demo")
    public String fromMachine() {
        return "Hello from system account authenticated protected method";
    }
}
