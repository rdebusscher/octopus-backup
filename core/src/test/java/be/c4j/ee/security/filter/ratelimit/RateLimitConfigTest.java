package be.c4j.ee.security.filter.ratelimit;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class RateLimitConfigTest {

    private RateLimitConfig config;

    @Test
    public void createRateLimiter_seconds() {
        config = new RateLimitConfig();
        FixedBucket rateLimiter = config.createRateLimiter("10/1s");

        assertThat(rateLimiter).isNotNull();
        assertThat(rateLimiter.getDuration()).isEqualTo(1);
        assertThat(rateLimiter.getAllowedRequests()).isEqualTo(10);
    }

    @Test
    public void createRateLimiter_minutes() {
        config = new RateLimitConfig();
        FixedBucket rateLimiter = config.createRateLimiter("1000/5m");

        assertThat(rateLimiter).isNotNull();
        assertThat(rateLimiter.getDuration()).isEqualTo(300);
        assertThat(rateLimiter.getAllowedRequests()).isEqualTo(1000);
    }

    @Test
    public void createRateLimiter_hours() {
        config = new RateLimitConfig();
        FixedBucket rateLimiter = config.createRateLimiter("100000/1h");

        assertThat(rateLimiter).isNotNull();
        assertThat(rateLimiter.getDuration()).isEqualTo(3600);
        assertThat(rateLimiter.getAllowedRequests()).isEqualTo(100000);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void createRateLimiter_MissingTimeValue() {
        config = new RateLimitConfig();
        config.createRateLimiter("1000/s");


    }

}