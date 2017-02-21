package be.c4j.ee.security.log;

import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.Properties;

/**
 *
 */
@ApplicationScoped
public class InfoVersionLogging {

    @Inject
    private Logger logger;

    private String releaseVersion;
    private String buildTime;

    @PostConstruct
    public void init() {

        Properties properties = new Properties();
        try {
            URL manifestFile = findManifestFile();

            InputStream resourceAsStream = manifestFile.openStream();
            if (resourceAsStream != null) {
                properties.load(resourceAsStream);
            }

            if (resourceAsStream != null) {
                resourceAsStream.close();
            }

        } catch (IOException e) {
            logger.warn("Exception during loading of the Octopus Core MANIFEST.MF file", e);
        }

        releaseVersion = properties.getProperty("Release-Version");
        buildTime = properties.getProperty("buildTime");

    }

    private URL findManifestFile() throws IOException {
        URL result = null;
        ClassLoader classLoader = this.getClass().getClassLoader();
        Enumeration<URL> systemResources = classLoader.getResources("META-INF/MANIFEST.MF");
        while (systemResources.hasMoreElements() && result == null) {
            URL url = systemResources.nextElement();
            if (url.toExternalForm().contains("/octopus-core-")) {
                result = url;
            }
        }
        return result;
    }

    public void showVersionInfo() {
        logger.info("Running on Octopus version " + releaseVersion + " (released on " + buildTime + " )");
    }
}
