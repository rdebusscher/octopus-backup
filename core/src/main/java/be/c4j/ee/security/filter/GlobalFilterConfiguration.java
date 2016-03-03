package be.c4j.ee.security.filter;

import org.apache.shiro.web.servlet.AdviceFilter;

import java.util.List;
import java.util.Map;

/**
 *
 */
public interface GlobalFilterConfiguration {

    Map<String, Class<? extends AdviceFilter>> getGlobalFilters();

    List<String> addFiltersTo(String url);

}
