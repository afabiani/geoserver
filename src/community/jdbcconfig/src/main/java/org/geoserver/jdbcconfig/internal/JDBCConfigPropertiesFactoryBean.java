package org.geoserver.jdbcconfig.internal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.geoserver.jdbcloader.JDBCLoaderProperties;
import org.geoserver.jdbcloader.JDBCLoaderPropertiesFactoryBean;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.platform.GeoServerResourceLoader;
import org.geoserver.platform.resource.Files;
import org.geoserver.platform.resource.Paths;
import org.geoserver.platform.resource.Resource;
import org.geoserver.platform.resource.ResourceStore;
import org.geoserver.platform.resource.Resources;

public class JDBCConfigPropertiesFactoryBean extends JDBCLoaderPropertiesFactoryBean {
    
    static final String PREFIX = "jdbcconfig";
    
    /**
     * DDL scripts copied to <data dir>/jdbcconfig_scripts/ on first startup
     */
    private static final String[] SCRIPTS = { "dropdb.h2.sql", "dropdb.mssql.sql",
            "dropdb.mysql.sql", "dropdb.oracle.sql", "dropdb.postgres.sql", "initdb.h2.sql",
            "initdb.mssql.sql", "initdb.mysql.sql", "initdb.oracle.sql", "initdb.postgres.sql" };

    private static final String[] SAMPLE_CONFIGS = { "jdbcconfig.properties.h2",
            "jdbcconfig.properties.postgres" };
    
    public JDBCConfigPropertiesFactoryBean(ResourceStore resourceStore) {
        super(resourceStore, PREFIX);
    }

    @Override
    protected JDBCLoaderProperties createConfig() throws IOException {
        return new JDBCConfigProperties(this);
    }

    @Override
    protected String[] getScripts() {
        return SCRIPTS;
    }

    @Override
    protected String[] getSampleConfigurations() {
        return SAMPLE_CONFIGS;
    }

    @Override
    public List<Resource> getFileLocations() throws IOException {
        List<Resource> configurationFiles = new ArrayList<>();
        
        final Resource scriptsDir = getScriptDir();
        for (String scriptName : getScripts()) {
            configurationFiles.add(scriptsDir.get(scriptName));
        }
        
        final Resource baseDirectory = getBaseDir();
        for (String sampleConfig : getSampleConfigurations()) {
            configurationFiles.add(baseDirectory.get(sampleConfig));
        }
        
        return configurationFiles;
    }

    @Override
    public void saveConfiguration(GeoServerResourceLoader resourceLoader) throws IOException {
        GeoServerResourceLoader loader = GeoServerExtensions.bean(GeoServerResourceLoader.class);
        for(Resource controlflow : getFileLocations()) {
            Resource targetDir = 
                    Files.asResource(resourceLoader.findOrCreateDirectory(Paths.convert(loader.getBaseDirectory(), controlflow.parent().dir())));
            
            Resources.copy(controlflow.file(), targetDir);
        }
    }

    @Override
    public void loadConfiguration(GeoServerResourceLoader resourceLoader) throws IOException {
        loadProperties(createProperties());
    }

}
