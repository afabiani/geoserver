/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.backuprestore.tasklet;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

import org.geoserver.backuprestore.Backup;
import org.geoserver.backuprestore.utils.BackupUtils;
import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.WorkspaceInfo;
import org.geoserver.config.GeoServer;
import org.geoserver.config.ServiceInfo;
import org.geoserver.config.util.XStreamPersister;
import org.geoserver.config.util.XStreamPersisterFactory;
import org.geoserver.config.util.XStreamServiceLoader;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.platform.resource.Resource;
import org.geoserver.platform.resource.Resources;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.UnexpectedJobExecutionException;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import com.thoughtworks.xstream.XStream;

/**
 * TODO
 * 
 * @author Alessio Fabiani, GeoSolutions
 *
 */
public class CatalogBackupTasklet implements Tasklet, InitializingBean {

    private Backup backupFacade;

    private Catalog catalog;

    private XStreamPersister xstream;

    private XStream xp;
    
    public CatalogBackupTasklet(Backup backupFacade,
            XStreamPersisterFactory xStreamPersisterFactory) {
        this.backupFacade = backupFacade;
        
        this.xstream = xStreamPersisterFactory.createXMLPersister();
        this.xstream.setCatalog(catalog);
        this.xstream.setReferenceByName(true);
        this.xstream.setExcludeIds();
        this.xp = this.xstream.getXStream();
    }

    @Override
    public RepeatStatus execute(StepContribution contribution, ChunkContext chunkContext)
            throws Exception {

        // Accordingly to the running execution type (Backup or Restore) we
        // need to validate resources against the official GeoServer Catalog (Backup)
        // or the temporary one (Restore).
        //
        // For restore operations the order matters.
        JobExecution jobExecution = chunkContext.getStepContext().getStepExecution()
                .getJobExecution();
        if (backupFacade.getRestoreExecutions() != null
                && !backupFacade.getRestoreExecutions().isEmpty()
                && backupFacade.getRestoreExecutions().containsKey(jobExecution.getId())) {
            this.catalog = backupFacade.getRestoreExecutions().get(jobExecution.getId())
                    .getRestoreCatalog();
        } else {
            this.catalog = backupFacade.getCatalog();
        }

        Assert.notNull(catalog, "catalog must be set");

        final GeoServer geoserver = backupFacade.getGeoServer();
        
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
                doWrite(service, targetBackupFolder, "services");
            }
            
            // Save Workspace specific settings
            Resource targetWorkspacesFolder = BackupUtils.dir(targetBackupFolder, "workspaces");
            
            // Store Default Workspace
            doWrite(catalog.getDefaultNamespace(), targetWorkspacesFolder, "defaultnamespace.xml");
            doWrite(catalog.getDefaultWorkspace(), targetWorkspacesFolder, "default.xml");
            
            // Store Workspace Specific Settings
            for (WorkspaceInfo ws : catalog.getWorkspaces()) {
                if (geoserver.getSettings(ws) != null) {
                    doWrite(geoserver.getSettings(ws), BackupUtils.dir(targetWorkspacesFolder, ws.getName()), "settings.xml");
                }
                
                if (geoserver.getServices(ws) != null) {
                    for (ServiceInfo service : geoserver.getServices(ws)) {
                        doWrite(service, targetWorkspacesFolder, ws.getName());
                    }
                }
            }
        } catch (Exception e) {
            throw new UnexpectedJobExecutionException("Exception occurred while storing GeoServer globals and services settings!", e);            
        }

        return RepeatStatus.FINISHED;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(backupFacade, "backupFacade must be set");
        Assert.notNull(xstream, "xstream must be set");
    }

    //
    public void doWrite(Object item, Resource directory, String fileName) throws IOException {
        if (item instanceof ServiceInfo) {
            ServiceInfo service = (ServiceInfo) item;
            XStreamServiceLoader loader = findServiceLoader(service);

            try {
                loader.save(service, backupFacade.getGeoServer(), BackupUtils.dir(directory, fileName));
            } catch (Throwable t) {
                throw new RuntimeException( t );
                //LOGGER.log(Level.SEVERE, "Error occurred while saving configuration", t);
            }
        } else {
            // unwrap dynamic proxies
            OutputStream out = Resources.fromPath(fileName, directory).out();
            try {
                item = xstream.unwrapProxies(item);
                xp.toXML(item, out);
            } finally {
                out.close();
            }
        }
    }
    
    XStreamServiceLoader findServiceLoader(ServiceInfo service) {
        XStreamServiceLoader loader = null;
        
        final List<XStreamServiceLoader> loaders = 
                GeoServerExtensions.extensions( XStreamServiceLoader.class );
        for ( XStreamServiceLoader<ServiceInfo> l : loaders  ) {
            if ( l.getServiceClass().isInstance( service ) ) {
                loader = l;
                break;
            }
        }

        if (loader == null) {
            throw new IllegalArgumentException("No loader for " + service.getName());
        }
        return loader;
    }
    
}
