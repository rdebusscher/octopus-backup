package be.c4j.demo;

import be.c4j.ee.security.context.OctopusSecurityContext;
import org.apache.shiro.authz.annotation.RequiresUser;

import javax.ejb.AsyncResult;
import javax.ejb.Asynchronous;
import javax.ejb.Stateless;
import java.util.concurrent.Future;

/**
 *
 */
@Stateless
@RequiresUser
public class WorkerService {

    @Asynchronous
    public Future<String> doInBackground(OctopusSecurityContext securityContext) {
        try {
            Thread.sleep(100L);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return new AsyncResult<String>("Hello World");
    }
}
