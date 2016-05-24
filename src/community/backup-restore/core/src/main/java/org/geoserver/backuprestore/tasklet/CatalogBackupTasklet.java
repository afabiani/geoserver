/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.backuprestore.tasklet;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.geoserver.backuprestore.Backup;
import org.geoserver.backuprestore.utils.BackupUtils;
import org.geoserver.catalog.CoverageInfo;
import org.geoserver.catalog.CoverageStoreInfo;
import org.geoserver.catalog.DataStoreInfo;
import org.geoserver.catalog.FeatureTypeInfo;
import org.geoserver.catalog.LayerGroupInfo;
import org.geoserver.catalog.LayerInfo;
import org.geoserver.catalog.NamespaceInfo;
import org.geoserver.catalog.StyleInfo;
import org.geoserver.catalog.WorkspaceInfo;
import org.geoserver.config.GeoServer;
import org.geoserver.config.GeoServerDataDirectory;
import org.geoserver.config.GeoServerInfo;
import org.geoserver.config.GeoServerPluginConfigurator;
import org.geoserver.config.GeoServerPropertyConfigurer;
import org.geoserver.config.LoggingInfo;
import org.geoserver.config.ServiceInfo;
import org.geoserver.config.SettingsInfo;
import org.geoserver.config.util.XStreamPersisterFactory;
import org.geoserver.gwc.config.GWCInitializer;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.platform.GeoServerResourceLoader;
import org.geoserver.platform.resource.Files;
import org.geoserver.platform.resource.Paths;
import org.geoserver.platform.resource.Resource;
import org.geoserver.platform.resource.ResourceStore;
import org.geoserver.platform.resource.Resources;
import org.geoserver.util.Filter;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.UnexpectedJobExecutionException;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.repeat.RepeatStatus;

import com.thoughtworks.xstream.io.StreamException;

/**
 * TODO
 * 
 * @author Alessio Fabiani, GeoSolutions
 *
 */
public class CatalogBackupTasklet extends AbstractCatalogBackupRestoreTasklet {
    
    public CatalogBackupTasklet(Backup backupFacade,
            XStreamPersisterFactory xStreamPersisterFactory) {
        super(backupFacade, xStreamPersisterFactory);
    }

    @Override
    RepeatStatus doExecute(StepContribution contribution, ChunkContext chunkContext, JobExecution jobExecution) {
        final GeoServer geoserver = backupFacade.getGeoServer();
        final GeoServerDataDirectory dd = backupFacade.getGeoServerDataDirectory();
        final ResourceStore resourceStore = dd.getResourceStore();
        
        try {
            if (!isNew()) {
                doBackup(jobExecution, geoserver, dd, resourceStore);
            } else {
                doRestore(jobExecution, geoserver, dd);
            }
        } catch (Exception e) {
            if(!isBestEffort()) {
                getCurrentJobExecution().addFailureExceptions(Arrays.asList(e));
                throw new UnexpectedJobExecutionException("Exception occurred while storing GeoServer globals and services settings!", e);
            } else {
                getCurrentJobExecution().addWarningExceptions(Arrays.asList(e));
            }
        }

        return RepeatStatus.FINISHED;
    }

    /**
     * Perform Backup
     * 
     * @param jobExecution
     * @param geoserver
     * @param dd
     * @param resourceStore
     * @throws IOException
     */
    private void doBackup(JobExecution jobExecution, final GeoServer geoserver,
            final GeoServerDataDirectory dd, final ResourceStore resourceStore) {
        try {
            final String outputFolderURL = jobExecution.getJobParameters().getString(Backup.PARAM_OUTPUT_FILE_PATH);
            Resource targetBackupFolder = Resources.fromURL(outputFolderURL);
            
            // Store GeoServer Global Info
            doWrite(geoserver.getGlobal(), targetBackupFolder, "global.xml");
            
            // Store GeoServer Global Settings
            doWrite(geoserver.getSettings(), targetBackupFolder, "settings.xml");
          
            // Store GeoServer Global Logging Settings
            doWrite(geoserver.getLogging(), targetBackupFolder, "logging.xml");
            
            // Store GeoServer Global Services
            for(ServiceInfo service : geoserver.getServices()) {
                // Local Services will be saved later on ...
                if (service.getWorkspace() == null) {
                    doWrite(service, targetBackupFolder, "services");
                }
            }
            
            // Save Workspace specific settings
            Resource targetWorkspacesFolder = BackupUtils.dir(targetBackupFolder, "workspaces");
            
            // Store Default Workspace
            doWrite(catalog.getDefaultNamespace(), targetWorkspacesFolder, "defaultnamespace.xml");
            doWrite(catalog.getDefaultWorkspace(), targetWorkspacesFolder, "default.xml");
            
            // Store Workspace Specific Settings and Services
            for (WorkspaceInfo ws : catalog.getWorkspaces()) {
                if (geoserver.getSettings(ws) != null) {
                    doWrite(geoserver.getSettings(ws), BackupUtils.dir(targetWorkspacesFolder, ws.getName()), "settings.xml");
                }
                
                if (geoserver.getServices(ws) != null) {
                    for (ServiceInfo service : geoserver.getServices(ws)) {
                        doWrite(service, targetWorkspacesFolder, ws.getName());
                    }
                }
                
                // Backup other configuration bits, like images, palettes, user projections and so on...
                GeoServerDataDirectory wsDd = new GeoServerDataDirectory(dd.get(Paths.path("workspaces", ws.getName())).dir());
                backupRestoreAdditionalResources(wsDd.getResourceStore(), targetWorkspacesFolder.get(ws.getName()));
                
                // Backup Style SLDs
                for (StyleInfo sty : catalog.getStylesByWorkspace(ws)) {
                    Resource styResource = wsDd.get(Paths.path("styles", sty.getFilename()));
                    if (Resources.exists(styResource)) {
                        Resources.copy(styResource.file(), BackupUtils.dir(targetWorkspacesFolder.get(ws.getName()), "styles"));
                    }
                }
            }
            
            // Backup GeoServer Plugins
            final GeoServerResourceLoader targetGeoServerResourceLoader = new GeoServerResourceLoader(targetBackupFolder.dir());
            for (GeoServerPluginConfigurator pluginConfig : GeoServerExtensions.extensions(GeoServerPluginConfigurator.class)) {
                // On restore invoke 'pluginConfig.loadConfiguration(resourceLoader);' after having replaced the config files.  
                pluginConfig.saveConfiguration(targetGeoServerResourceLoader);
            }
            
            for (GeoServerPropertyConfigurer props : GeoServerExtensions.extensions(GeoServerPropertyConfigurer.class)) {
                // On restore invoke 'props.reload();' after having replaced the properties files.
                Resource configFile = props.getConfigFile();
                
                if (configFile != null && Resources.exists(configFile)) {
                    Resource targetDir = 
                        Files.asResource(targetGeoServerResourceLoader.findOrCreateDirectory(
                                Paths.convert(dd.getResourceLoader().getBaseDirectory(), configFile.parent().dir())));
                
                    Resources.copy(configFile.file(), targetDir);
                }
            }
            
            // Backup other configuration bits, like images, palettes, user projections and so on...
            backupRestoreAdditionalResources(resourceStore, targetBackupFolder);
            
            // Backup GWC Configuration bits
            if (GeoServerExtensions.bean("gwcGeoServervConfigPersister") != null) {
                backupGWCSettings(targetBackupFolder);
            }
        } catch (Exception e) {
            if(!isBestEffort()) {
                getCurrentJobExecution().addFailureExceptions(Arrays.asList(e));
                throw new UnexpectedJobExecutionException("Exception occurred while storing GeoServer globals and services settings!", e);
            } else {
                getCurrentJobExecution().addWarningExceptions(Arrays.asList(e));
            }
        }
    }
    
    /**
     * @param jobExecution
     * @param geoserver
     * @param dd
     * @throws IOException
     * @throws UnexpectedJobExecutionException
     */
    @SuppressWarnings("unused")
    private void doRestore(JobExecution jobExecution, final GeoServer geoserver,
            final GeoServerDataDirectory dd) {
        final String inputFolderURL = jobExecution.getJobParameters().getString(Backup.PARAM_INPUT_FILE_PATH);
        Resource sourceRestoreFolder = Resources.fromURL(inputFolderURL);
        Resource sourceWorkspacesFolder = null;
        
        // Try first to load all the settings available into the source restore folder
        GeoServerInfo newGeoServerInfo = null;
        SettingsInfo newSettings = null;
        LoggingInfo newLoggingInfo = null;
        try {
            newGeoServerInfo = (GeoServerInfo) doRead(sourceRestoreFolder, "global.xml");
            newSettings= (SettingsInfo) doRead(sourceRestoreFolder, "settings.xml");
            newLoggingInfo= (LoggingInfo) doRead(sourceRestoreFolder, "logging.xml");
        } catch (Exception e) {
            if(!isBestEffort()) {
                getCurrentJobExecution().addFailureExceptions(Arrays.asList(e));
                throw new UnexpectedJobExecutionException("Exception occurred while storing GeoServer globals and services settings!", e);
            } else {
                getCurrentJobExecution().addWarningExceptions(Arrays.asList(e));
            }
        }
        
        // Save Workspace specific settings
        try {
            sourceWorkspacesFolder = BackupUtils.dir(sourceRestoreFolder, "workspaces");
            // Set Default Namespace and Workspace
            NamespaceInfo newDefaultNamespace = (NamespaceInfo) doRead(sourceWorkspacesFolder, "defaultnamespace.xml");
            WorkspaceInfo newDefaultWorkspace = (WorkspaceInfo) doRead(sourceWorkspacesFolder, "default.xml");
            this.catalog.setDefaultNamespace(newDefaultNamespace);
            this.catalog.setDefaultWorkspace(newDefaultWorkspace);            
        } catch (Exception e) {
            if(!isBestEffort()) {
                getCurrentJobExecution().addFailureExceptions(Arrays.asList(e));
                throw new UnexpectedJobExecutionException("Exception occurred while storing GeoServer globals and services settings!", e);
            } else {
                getCurrentJobExecution().addWarningExceptions(Arrays.asList(e));
            }
        }
        
        // RESTORE
        // TODO: Save old settings
        /*GeoServerInfo oldGeoServerInfo = geoserver.getGlobal();
        SettingsInfo oldSettings = geoserver.getSettings();
        LoggingInfo oldLoggingInfo = geoserver.getLogging();
        WorkspaceInfo oldDefaultWorkspace = geoserver.getCatalog().getDefaultWorkspace();
        NamespaceInfo oldDefaultNamespace = geoserver.getCatalog().getDefaultNamespace();*/
        
        // Do this *ONLY* when DRY-RUN-MODE == OFF
        if (!isDryRun()) {
            try {
                hardRestore(geoserver, dd, sourceRestoreFolder, sourceWorkspacesFolder, newGeoServerInfo, newLoggingInfo);
            } catch (Exception e) {
                if(!isBestEffort()) {
                    getCurrentJobExecution().addFailureExceptions(Arrays.asList(e));
                    throw new UnexpectedJobExecutionException("Exception occurred while storing GeoServer globals and services settings!", e);
                } else {
                    getCurrentJobExecution().addWarningExceptions(Arrays.asList(e));
                }
            } finally {
                /*
                TODO:
                    - Handle Revert ??
                */
            }
        } else {
            // DRY-RUN-MODE ON: Try to check backup files consistency as much as possible
            try {
                // Temporary GeoServer Data Dir just for testing
                GeoServerDataDirectory td = new GeoServerDataDirectory(BackupUtils.tmpDir().dir());
                softRestore(geoserver, td, sourceRestoreFolder, sourceWorkspacesFolder, newGeoServerInfo, newLoggingInfo);
            } catch (Exception e) {
                if(!isBestEffort()) {
                    getCurrentJobExecution().addFailureExceptions(Arrays.asList(e));
                    throw new UnexpectedJobExecutionException("Exception occurred while storing GeoServer globals and services settings!", e);
                } else {
                    getCurrentJobExecution().addWarningExceptions(Arrays.asList(e));
                }
            } finally {
            }
        }
    }

    /**
     * @param geoserver
     * @param dd
     * @param sourceRestoreFolder
     * @param newGeoServerInfo
     * @param newLoggingInfo
     * @param sourceWorkspacesFolder
     * @throws IOException
     * @throws Exception
     * @throws IllegalArgumentException
     */
    private void hardRestore(final GeoServer geoserver, final GeoServerDataDirectory dd,
            Resource sourceRestoreFolder, Resource sourceWorkspacesFolder, GeoServerInfo newGeoServerInfo,
            LoggingInfo newLoggingInfo)
            throws IOException, Exception, IllegalArgumentException {
        // TODO: add option 'cleanUpGeoServerDataDir'
        // TODO: purge/preserve GEOSERVER_DATA_DIR
        geoserver.getCatalog().getResourcePool().dispose();
        geoserver.getCatalog().dispose();
        geoserver.dispose();

        // Restore GeoServer Global Info
        Files.delete(dd.get("global.xml").file());
        doWrite(newGeoServerInfo, dd.get(Paths.BASE), "global.xml");
        geoserver.setGlobal(newGeoServerInfo);

        // Restore GeoServer Global Logging Settings
        Files.delete(dd.get("logging.xml").file());
        doWrite(newLoggingInfo, dd.get(Paths.BASE), "logging.xml");
        geoserver.setLogging(newLoggingInfo);
        
        restoreGlobalServices(sourceRestoreFolder, dd);
        
        // Restore Workspaces
        // - Prepare folder
        Resource workspaces = dd.get("workspaces");
        // - TODO: if purge
        Files.delete(workspaces.dir());
        workspaces = BackupUtils.dir(dd.get(Paths.BASE), "workspaces");
        
        restoreWorkSpacesAndLayers(workspaces);

        // Restore GeoServer Settings
        // - GeoServer Catalog Alignment
        geoserver.reload(this.catalog);

        // Restore Styles
        // - Prepare folder
        Resource styles = dd.get("styles");
        // - TODO: if purge
        Files.delete(styles.dir());
        styles = BackupUtils.dir(dd.get(Paths.BASE), "styles");
        
        restoreLocalServices(sourceRestoreFolder, styles);
        
        // Restore LayerGroups
        // - Prepare folder
        Resource layerGroups = dd.get("layergroups");
        // - TODO: if purge
        Files.delete(layerGroups.dir());
        layerGroups = BackupUtils.dir(dd.get(Paths.BASE), "layergroups");
        
        restoreLayerGroups(layerGroups);

        // Restore Workspace Specific Settings and Services
        restoreLocalWorkspaceSettingsAndServices(geoserver, sourceRestoreFolder,
                sourceWorkspacesFolder, dd);

        // Restore GeoServer Plugins
        final GeoServerResourceLoader sourceGeoServerResourceLoader = new GeoServerResourceLoader(sourceRestoreFolder.dir());
        for (GeoServerPluginConfigurator pluginConfig : GeoServerExtensions.extensions(GeoServerPluginConfigurator.class)) {
            // On restore invoke 'pluginConfig.loadConfiguration(resourceLoader);'. Replace 'properties' files first.
            for (Resource configFile : pluginConfig.getFileLocations()) {
                replaceConfigFile(sourceGeoServerResourceLoader, configFile);
            }
            
            // - Invoke 'pluginConfig.loadConfiguration' from the GOSERVER_DATA_DIR
            pluginConfig.loadConfiguration(dd.getResourceLoader());
        }

        for (GeoServerPropertyConfigurer props : GeoServerExtensions.extensions(GeoServerPropertyConfigurer.class)) {
            // On restore invoke 'props.reload();' after having replaced the properties files.
            Resource configFile = props.getConfigFile();
            replaceConfigFile(sourceGeoServerResourceLoader, configFile);

            // - Invoke 'props.reload()' from the GOSERVER_DATA_DIR
            props.reload();
        }
        
        // Restore other configuration bits, like images, palettes, user projections and so on...
        backupRestoreAdditionalResources(sourceGeoServerResourceLoader, dd.get(Paths.BASE));
        
        // Restore GWC Configuration bits
        if (GeoServerExtensions.bean("gwcGeoServervConfigPersister") != null) {
            restoreGWCSettings(sourceRestoreFolder, dd.get(Paths.BASE));
            
            // Initialize GWC with the new settings
            GWCInitializer gwcInitializer = GeoServerExtensions.bean(GWCInitializer.class);
            if (gwcInitializer != null) {
                gwcInitializer.initialize(geoserver);
            }
        }
    }

    /**
     * @param geoserver
     * @param td 
     * @param sourceRestoreFolder
     * @param sourceWorkspacesFolder
     * @param newGeoServerInfo
     * @param newLoggingInfo
     * @throws IOException
     */
    private void softRestore(final GeoServer geoserver, GeoServerDataDirectory td, Resource sourceRestoreFolder,
            Resource sourceWorkspacesFolder, GeoServerInfo newGeoServerInfo,
            LoggingInfo newLoggingInfo) throws IOException {
        // Restore GeoServer Global Info
        doWrite(newGeoServerInfo, td.get(Paths.BASE), "global.xml");

        // Restore GeoServer Global Logging Settings
        doWrite(newLoggingInfo, td.get(Paths.BASE), "logging.xml");
        
        // Restore GeoServer Global Services
        restoreGlobalServices(sourceRestoreFolder, td);
        
        // Restore Workspaces
        // - Prepare folder
        BackupUtils.dir(td.get(Paths.BASE), "workspaces");
        Resource workspaces = td.get("workspaces");
        
        restoreWorkSpacesAndLayers(workspaces);

        // Restore Styles
        // - Prepare folder
        BackupUtils.dir(td.get(Paths.BASE), "styles");
        Resource styles = td.get("styles");
        
        restoreLocalServices(sourceRestoreFolder, styles);
        
        // Restore LayerGroups
        // - Prepare folder
        BackupUtils.dir(td.get(Paths.BASE), "layergroups");
        Resource layerGroups = td.get("layergroups");
        
        // Workspace Local LayerGroups
        restoreLayerGroups(layerGroups);

        // Restore Workspace Specific Settings and Services
        restoreLocalWorkspaceSettingsAndServices(geoserver, sourceRestoreFolder,
                sourceWorkspacesFolder, td);

        // Restore GeoServer Plugins
        final GeoServerResourceLoader sourceGeoServerResourceLoader = new GeoServerResourceLoader(sourceRestoreFolder.dir());
        
        // Restore other configuration bits, like images, palettes, user projections and so on...
        backupRestoreAdditionalResources(sourceGeoServerResourceLoader, td.get(Paths.BASE));
        
        // Restore GWC Configuration bits
        if (GeoServerExtensions.bean("gwcGeoServervConfigPersister") != null) {
            restoreGWCSettings(sourceRestoreFolder, td.get(Paths.BASE));                    
        }
        
        // Cleanup Temp Folder
        Files.delete(td.get(Paths.BASE).dir());
    }
    
    /**
     * @param resourceLoader
     * @param configFile
     * @throws IOException
     */
    private void replaceConfigFile(final GeoServerResourceLoader resourceLoader, Resource configFile) throws IOException {
        // - Check of the resource exists on the restore folder
        Resource rstConfigFile = Files.asResource(resourceLoader.find(
                Paths.path(configFile.file().getParent(), configFile.file().getName())));
        
        // - Copy the resource into the GOSERVER_DATA_DIR (overwriting the old one if exists)
        if (Resources.exists(rstConfigFile)) {
            Resources.copy(rstConfigFile.file(), configFile.parent());
        }
    }
    
    /**
     * @param geoserver
     * @param sourceRestoreFolder
     * @param sourceWorkspacesFolder
     * @param dd
     * @throws IOException
     */
    private void restoreLocalWorkspaceSettingsAndServices(final GeoServer geoserver,
            Resource sourceRestoreFolder, Resource sourceWorkspacesFolder,
            GeoServerDataDirectory dd) throws IOException {
        for (WorkspaceInfo ws : geoserver.getCatalog().getWorkspaces()) {
            Resource wsFolder = BackupUtils.dir(sourceWorkspacesFolder, ws.getName());
            SettingsInfo wsSettings = null;
            if (Resources.exists(wsFolder.get("settings.xml"))) {
                wsSettings = (SettingsInfo) doRead(wsFolder, "settings.xml");
            }
        
            if (wsSettings != null) {
                wsSettings.setWorkspace(ws);
                if(!isDryRun()) {
                    geoserver.add(wsSettings);
                    doWrite(geoserver.getSettings(ws), dd.get(Paths.path("workspaces", ws.getName())), "settings.xml");
                } else {
                    doWrite(wsSettings, dd.get(Paths.path("workspaces", ws.getName())), "settings.xml");
                }
            }

            // Restore Workspace Local Services
            List<Resource> serviceResources = Resources.list(wsFolder, new Filter<Resource>() {

                @Override
                public boolean accept(Resource res) {
                    if (!"settings.xml".equals(res.name()) && res.name().endsWith(".xml")) {
                        return true;
                    }
                    return false;
                }
                
            });
            for (Resource serviceResource : serviceResources) {
                ServiceInfo localService = 
                        (ServiceInfo) doRead(wsFolder, serviceResource.name());
                if (localService != null) {
                    localService.setWorkspace(ws);
                    if(!isDryRun()) {
                        geoserver.add(localService);
                    }
                    doWrite(localService, 
                            dd.get(Paths.path("workspaces", ws.getName())), "");
                }
            }
            
            // Restore Local Styles
            for (StyleInfo sty : this.catalog.getStylesByWorkspace(ws.getName())) {
                // Only Local Services here.
                sty.setWorkspace(ws);
                Resource wsLocalStyleFolder = BackupUtils.dir(dd.get(Paths.path("workspaces", ws.getName())), "styles");
                doWrite(sty, wsLocalStyleFolder, sty.getName() + ".xml");

                Resource styResource = sourceRestoreFolder.get(Paths.path("workspaces", ws.getName(), "styles", sty.getFilename()));
                if (Resources.exists(styResource)) {
                    Resources.copy(styResource.file(), wsLocalStyleFolder);
                }
            }

            // Restore Local LayerGroups
            for (LayerGroupInfo lyg : this.catalog.getLayerGroupsByWorkspace(ws.getName())) {
                // Only Local LayerGroups here.
                lyg.setWorkspace(ws);
                Resource wsLocalLayerGroupsFolder = BackupUtils.dir(dd.get(Paths.path("workspaces", ws.getName())), "layergroups");
                doWrite(lyg, wsLocalLayerGroupsFolder, lyg.getName() + ".xml");
            }
        }
    }

    /**
     * @param layerGroups
     */
    private void restoreLayerGroups(Resource layerGroups) {
        for (LayerGroupInfo lyg : this.catalog.getLayerGroups()) {
            // Only Global LayerGroups here; local ones will be restored later on
            if (lyg.getWorkspace() == null) {
                doWrite(lyg, layerGroups, lyg.getName() + ".xml");
            }
        }
    }

    /**
     * @param sourceRestoreFolder
     * @param styles
     * @throws IOException
     */
    private void restoreLocalServices(Resource sourceRestoreFolder, Resource styles)
            throws IOException {
        for (StyleInfo sty : this.catalog.getStyles()) {
            // Only Global Services here. Local ones will be restored later on
            if (sty.getWorkspace() == null) {
                doWrite(sty, styles, sty.getName() + ".xml");
            
                Resource styResource = sourceRestoreFolder.get(Paths.path("styles", sty.getFilename()));
                if (Resources.exists(styResource)) {
                    Resources.copy(styResource.file(), styles);
                }
            }
        }
    }

    /**
     * @param sourceRestoreFolder
     * @param td
     * @throws IOException
     */
    private void restoreGlobalServices(Resource sourceRestoreFolder, GeoServerDataDirectory td)
            throws IOException {
        for(Resource serviceResource : sourceRestoreFolder.get("services").list()) {
            // Local Services will be saved later on ...
            ServiceInfo service = (ServiceInfo) doRead(sourceRestoreFolder.get("services"), serviceResource.name());
            if (service != null && service.getWorkspace() == null) {
                Files.delete(td.get(serviceResource.name()).file());
                Resources.copy(
                        sourceRestoreFolder.get(Paths.path("services", serviceResource.name())).file(), td.get(Paths.BASE));
            }
        }
    }

    /**
     * @param workspaces
     */
    private void restoreWorkSpacesAndLayers(Resource workspaces) {
        // - Restore Default Workspace
        Files.delete(workspaces.get("default.xml").file());
        doWrite(this.catalog.getDefaultWorkspace(), workspaces, "default.xml");
        
        // - Restore Workspaces/Namespaces definitions and settings
        for (WorkspaceInfo ws : this.catalog.getWorkspaces()) {
            // Restore Workspace and Namespace confifuration
            // - Prepare Folder
            Files.delete(workspaces.get(ws.getName()).dir());
            Resource wsFolder = BackupUtils.dir(workspaces, ws.getName());

            doWrite(this.catalog.getNamespaceByPrefix(ws.getName()), wsFolder, "namespace.xml");
            doWrite(ws, wsFolder, "workspace.xml");
            
            // Restore DataStores/CoverageStores
            for (DataStoreInfo ds : this.catalog.getStoresByWorkspace(ws.getName(), DataStoreInfo.class)) {
                // - Prepare Folder
                Resource dsFolder = BackupUtils.dir(wsFolder, ds.getName());
                
                ds.setWorkspace(ws);
                
                doWrite(ds, dsFolder, "datastore.xml");
                
                // Restore Resources
                for (FeatureTypeInfo ft : this.catalog.getFeatureTypesByDataStore(ds)) {
                    // - Prepare Folder
                    Files.delete(dsFolder.get(ft.getName()).dir());
                    Resource ftFolder = BackupUtils.dir(dsFolder, ft.getName());
                
                    doWrite(ft, ftFolder, "featuretype.xml");
                    
                    // Restore Layers
                    for (LayerInfo ly : this.catalog.getLayers(ft)) {
                        doWrite(ly, ftFolder, "layer.xml");
                    }
                }
            }

            for (CoverageStoreInfo cs : this.catalog.getStoresByWorkspace(ws.getName(), CoverageStoreInfo.class)) {
                // - Prepare Folder
                Resource csFolder = BackupUtils.dir(wsFolder, cs.getName());
                
                cs.setWorkspace(ws);
                
                doWrite(cs, csFolder, "coveragestore.xml");
                
                // Restore Resources
                for (CoverageInfo ci : this.catalog.getCoveragesByCoverageStore(cs)) {
                    // - Prepare Folder
                    Files.delete(csFolder.get(ci.getName()).dir());
                    Resource ciFolder = BackupUtils.dir(csFolder, ci.getName());
                    
                    doWrite(ci, ciFolder, "coverage.xml");
                    
                    // Restore Layers
                    for (LayerInfo ly : this.catalog.getLayers(ci)) {
                        doWrite(ly, ciFolder, "layer.xml");
                    }
                }
            }                        
        }
    }
}
