package be.c4j.ee.security.credentials.authentication.oracle;

import javax.annotation.security.PermitAll;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

/**
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
public class OraclePasswordExecutor {

    @PersistenceContext
    private EntityManager em;

    @PermitAll
    public boolean checkPassword(String userName, String password) {
        Query nativeQuery = em.createNativeQuery("SELECT CHECK_PASSWORD(?, ?) FROM DUAL");
        nativeQuery.setParameter(1, userName);
        nativeQuery.setParameter(2, password);
        Object result = nativeQuery.getSingleResult();
        return "Y".equals(result);
    }
}
