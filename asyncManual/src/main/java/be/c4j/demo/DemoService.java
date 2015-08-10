package be.c4j.demo;

import be.c4j.ee.security.context.OctopusSecurityContext;

import javax.annotation.security.PermitAll;
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

    public String sayHello() {
        octopusSecurityContext.prepareForAsyncUsage();

        Future<String> stringFuture = workerService.doInBackground(octopusSecurityContext);
        String result = null;
        try {
            result = stringFuture.get(500L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        } catch (TimeoutException e) {
            e.printStackTrace();
        }
        return result;
    }
}
