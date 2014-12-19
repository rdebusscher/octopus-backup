package be.c4j.ee.security.util;

import javax.faces.context.FacesContext;
import javax.faces.event.PhaseId;

/**
 *
 */
public final class JsfUtils {

    private JsfUtils() {
    }

    public static boolean isRenderResponsePhase() {
        return PhaseId.RENDER_RESPONSE.equals(FacesContext.getCurrentInstance().getCurrentPhaseId());
    }

}
