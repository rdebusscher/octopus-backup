package be.c4j.ee.security.audit;

/**
 *
 */
public class OctopusAuditEvent {

    private String requestURI;
    private Object principal;
    private String remoteAddress;

    public OctopusAuditEvent(String requestURI, Object principal, String remoteAddress) {
        this.requestURI = requestURI;
        this.principal = principal;
        this.remoteAddress = remoteAddress;
    }

    public String getRequestURI() {
        return requestURI;
    }

    public Object getPrincipal() {
        return principal;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }
}
