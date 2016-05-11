/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2016 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.backuprestore;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;
import org.geoserver.backuprestore.utils.BackupUtils;
import org.geoserver.catalog.Catalog;
import org.geoserver.config.GeoServer;
import org.geoserver.config.GeoServerDataDirectory;
import org.geoserver.config.util.XStreamPersister;
import org.geoserver.config.util.XStreamPersisterFactory;
import org.geoserver.platform.ContextLoadedEvent;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.platform.GeoServerResourceLoader;
import org.geoserver.platform.resource.Resource;
import org.geotools.util.logging.Logging;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobParameters;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.JobParametersInvalidException;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.core.launch.JobOperator;
import org.springframework.batch.core.launch.NoSuchJobException;
import org.springframework.batch.core.repository.JobExecutionAlreadyRunningException;
import org.springframework.batch.core.repository.JobInstanceAlreadyCompleteException;
import org.springframework.batch.core.repository.JobRestartException;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

import com.thoughtworks.xstream.XStream;

/**
 * Primary controller/facade of the backup and restore subsystem.
 * 
 * @author Alessio Fabiani, GeoSolutions
 *
 */
public class Backup implements DisposableBean, ApplicationContextAware, ApplicationListener {

    static Logger LOGGER = Logging.getLogger(Backup.class);

    public static final String PARAM_TIME = "time";

    public static final String PARAM_OUTPUT_FILE_PATH = "output.file.path";

    public static final String PARAM_INPUT_FILE_PATH = "input.file.path";

    public static final String BACKUP_JOB_NAME = "backupJob";

    public static final String RESTORE_JOB_NAME = "restoreJob";

    public static final String RESTORE_CATALOG_KEY = "restore.catalog";

    /** catalog */
    Catalog catalog;

    GeoServer geoServer;

    GeoServerResourceLoader resourceLoader;

    GeoServerDataDirectory geoServerDataDirectory;

    XStreamPersisterFactory xpf;

    JobOperator jobOperator;

    JobLauncher jobLauncher;

    Job backupJob;

    Job restoreJob;

    ConcurrentHashMap<Long, BackupExecutionAdapter> backupExecutions = new ConcurrentHashMap<Long, BackupExecutionAdapter>();

    ConcurrentHashMap<Long, RestoreExecutionAdapter> restoreExecutions = new ConcurrentHashMap<Long, RestoreExecutionAdapter>();

    /**
     * A static application context
     */
    static ApplicationContext context;

    public Backup(Catalog catalog, GeoServerResourceLoader rl) {
        this.catalog = catalog;
        this.geoServer = GeoServerExtensions.bean(GeoServer.class);

        this.resourceLoader = rl;
        this.geoServerDataDirectory = new GeoServerDataDirectory(rl);
        
        this.xpf = GeoServerExtensions.bean(XStreamPersisterFactory.class);
    }

    /**
     * @return the jobOperator
     */
    public JobOperator getJobOperator() {
        return jobOperator;
    }

    /**
     * @return the jobLauncher
     */
    public JobLauncher getJobLauncher() {
        return jobLauncher;
    }

    /**
     * @return the Backup job
     */
    public Job getBackupJob() {
        return backupJob;
    }

    /**
     * @return the Restore job
     */
    public Job getRestoreJob() {
        return restoreJob;
    }

    /**
     * @return the backupExecutions
     */
    public ConcurrentHashMap<Long, BackupExecutionAdapter> getBackupExecutions() {
        return backupExecutions;
    }

    /**
     * @return the restoreExecutions
     */
    public ConcurrentHashMap<Long, RestoreExecutionAdapter> getRestoreExecutions() {
        return restoreExecutions;
    }

    @Override
    public void onApplicationEvent(ApplicationEvent event) {
        // load the context store here to avoid circular dependency on creation
        if (event instanceof ContextLoadedEvent) {
            this.jobOperator = (JobOperator) context.getBean("jobOperator");
            this.jobLauncher = (JobLauncher) context.getBean("jobLauncherAsync");

            this.backupJob = (Job) context.getBean(BACKUP_JOB_NAME);
            this.restoreJob = (Job) context.getBean(RESTORE_JOB_NAME);
        }
    }

    /**
     * @return
     */
    public Set<Long> getBackupRunningExecutions() {
        synchronized(jobOperator) {
            Set<Long> runningExecutions;
            try {
                runningExecutions = jobOperator.getRunningExecutions(BACKUP_JOB_NAME);
            } catch (NoSuchJobException e) {
                runningExecutions = new HashSet<>();
            }
            return runningExecutions;
        }
    }

    /**
     * @return
     */
    public Set<Long> getRestoreRunningExecutions() {
        synchronized(jobOperator) {
            Set<Long> runningExecutions;
            try {
                runningExecutions = jobOperator.getRunningExecutions(RESTORE_JOB_NAME);
            } catch (NoSuchJobException e) {
                runningExecutions = new HashSet<>();
            }
            return runningExecutions;
        }
    }

    public Catalog getCatalog() {
        return catalog;
    }

    public GeoServer getGeoServer() {
        return geoServer;
    }

    /**
     * @return the resourceLoader
     */
    public GeoServerResourceLoader getResourceLoader() {
        return resourceLoader;
    }

    /**
     * @param resourceLoader the resourceLoader to set
     */
    public void setResourceLoader(GeoServerResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    /**
     * @return the geoServerDataDirectory
     */
    public GeoServerDataDirectory getGeoServerDataDirectory() {
        return geoServerDataDirectory;
    }

    /**
     * @param geoServerDataDirectory the geoServerDataDirectory to set
     */
    public void setGeoServerDataDirectory(GeoServerDataDirectory geoServerDataDirectory) {
        this.geoServerDataDirectory = geoServerDataDirectory;
    }

    @Override
    public void destroy() throws Exception {
        // TODO Auto-generated method stub
    }

    @Override
    public void setApplicationContext(ApplicationContext context) throws BeansException {
        Backup.context = context;
    }

    protected String getItemName(XStreamPersister xp, Class clazz) {
        return xp.getClassAliasingMapper().serializedClass(clazz);
    }

    /**
     * @return 
     * @throws IOException 
     * 
     */
    public BackupExecutionAdapter runBackupAsync(final Resource archiveFile, final boolean overwrite) throws IOException {
        // Check if archiveFile exists
        if(archiveFile.file().exists()) {
            if (!overwrite) {
                // Unless the user explicitly wants to overwrite the archiveFile, throw an exception whenever it already exists
                throw new IOException("The target archive file already exists. Use 'overwrite=TRUE' if you want to overwrite it.");
            } else {
                FileUtils.forceDelete(archiveFile.file());
            }
        } else {
            // Make sure the parent path exists
            if (!archiveFile.file().getParentFile().exists()) {
                if (!archiveFile.file().getParentFile().mkdirs()) {
                    throw new IOException("The path to target archive file is unreachable.");
                }
            }
        }
        
        // Initialize ZIP
        FileUtils.touch(archiveFile.file());
        
        // Write flat files into a temporary folder
        Resource tmpDir = BackupUtils.tmpDir();

        JobParameters params = new JobParametersBuilder()
                .addString(PARAM_OUTPUT_FILE_PATH, BackupUtils.getArchiveURLProtocol(tmpDir) + tmpDir.path())
                .addLong(PARAM_TIME, System.currentTimeMillis())
                .toJobParameters();

        BackupExecutionAdapter backupExecution;
        try {
            if(getRestoreRunningExecutions().isEmpty() && 
                    getBackupRunningExecutions().isEmpty()) {
                synchronized(jobOperator) {
                    backupExecution = new BackupExecutionAdapter(jobLauncher.run(backupJob, params));
                    backupExecution.setArchiveFile(archiveFile);
                    backupExecution.setOverwrite(overwrite);
                    backupExecutions.put(backupExecution.getId(), backupExecution);

                    // LOGGER.fine("Status : " + backupExecution.getStatus());
                    
                    return backupExecution;
                }
            }
            else {
                // TODO: Else throw an Exception
                throw new IOException("Could not start a new Backup Job Execution since there are currently Running jobs.");
            }
        } catch (JobExecutionAlreadyRunningException | JobRestartException
                | JobInstanceAlreadyCompleteException | JobParametersInvalidException e) {
            // TODO
            throw new IOException(e);
        }
    }

    /**
     * @return
     * @return
     * @throws IOException
     * 
     */
    public RestoreExecutionAdapter runRestoreAsync(final Resource archiveFile) throws IOException {
        // Extract archive into a temporary folder
        Resource tmpDir = BackupUtils.tmpDir();
        BackupUtils.extractTo(archiveFile, tmpDir);

        JobParameters params = new JobParametersBuilder()
                .addString(PARAM_INPUT_FILE_PATH,
                        BackupUtils.getArchiveURLProtocol(tmpDir) + tmpDir.path())
                .addLong(PARAM_TIME, System.currentTimeMillis()).toJobParameters();

        RestoreExecutionAdapter restoreExecution;
        try {
            if (getRestoreRunningExecutions().isEmpty()
                    && getBackupRunningExecutions().isEmpty()) {
                synchronized (jobOperator) {
                    restoreExecution = new RestoreExecutionAdapter(jobLauncher.run(restoreJob, params));
                    restoreExecution.setArchiveFile(archiveFile);

                    restoreExecutions.put(restoreExecution.getId(), restoreExecution);

                    // LOGGER.fine("Status : " + restoreExecution.getStatus());

                    return restoreExecution;
                }
            }
            else {
                // TODO: Else throw an Exception
                throw new IOException("Could not start a new Restore Job Execution since there are currently Running jobs.");
            }
        } catch (JobExecutionAlreadyRunningException | JobRestartException
                | JobInstanceAlreadyCompleteException | JobParametersInvalidException e) {
            // TODO
            throw new IOException(e);
        }
    }

    public XStreamPersister createXStreamPersisterXML() {
        return initXStreamPersister(new XStreamPersisterFactory().createXMLPersister());
    }

    public XStreamPersister createXStreamPersisterJSON() {
        return initXStreamPersister(new XStreamPersisterFactory().createJSONPersister());
    }

    public XStreamPersister initXStreamPersister(XStreamPersister xp) {
        xp.setCatalog(catalog);
        // xp.setReferenceByName(true);

        XStream xs = xp.getXStream();

        // ImportContext
        xs.alias("backup", BackupExecutionAdapter.class);

        // security
        xs.allowTypes(new Class[] { BackupExecutionAdapter.class });
        xs.allowTypeHierarchy(Resource.class);

        return xp;
    }
}
