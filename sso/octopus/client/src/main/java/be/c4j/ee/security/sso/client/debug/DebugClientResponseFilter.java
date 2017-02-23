package be.c4j.ee.security.sso.client.debug;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientResponseFilter;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

/**
 *
 */

public class DebugClientResponseFilter implements ClientResponseFilter {

    private Logger logger = LoggerFactory.getLogger(DebugClientResponseFilter.class);

    private final int maxEntitySize = 1024 * 8;

    @Override
    public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) throws IOException {
        if (responseContext.hasEntity()) {
            responseContext.setEntityStream(logInboundEntity(responseContext.getEntityStream()));
        }
    }

    private InputStream logInboundEntity(InputStream stream) throws IOException {
        StringBuilder responseBody = new StringBuilder();
        InputStream logStream = stream;
        if (!stream.markSupported()) {
            logStream = new BufferedInputStream(stream);
        }
        logStream.mark(maxEntitySize + 1);
        final byte[] entity = new byte[maxEntitySize + 1];
        final int entitySize = logStream.read(entity);
        responseBody.append(new String(entity, 0, Math.min(entitySize, maxEntitySize), Charset.defaultCharset()));
        if (entitySize > maxEntitySize) {
            responseBody.append("...more...");
        }
        logStream.reset();

        logger.info("REST call body content " + responseBody.toString());
        return logStream;
    }
}
