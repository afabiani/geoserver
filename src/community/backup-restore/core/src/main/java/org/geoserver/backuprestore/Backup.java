/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.backuprestore;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
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
import org.geotools.factory.Hints;
import org.geotools.util.logging.Logging;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobParameters;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.JobParametersInvalidException;
import org.springframework.batch.core.job.AbstractJob;
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

    /* Job Parameters Keys **/
    public static final String PARAM_TIME = "time";

    public static final String PARAM_OUTPUT_FILE_PATH = "output.file.path";

    public static final String PARAM_INPUT_FILE_PATH = "input.file.path";

    public static final String PARAM_DRY_RUN_MODE = "BK_DRY_RUN";

    public static final String PARAM_BEST_EFFORT_MODE = "BK_BEST_EFFORT";
    
    /* Jobs Context Keys **/
    public static final String BACKUP_JOB_NAME = "backupJob";

    public static final String RESTORE_JOB_NAME = "restoreJob";

    public static final String RESTORE_CATALOG_KEY = "restore.catalog";

    /** The semaphore */
    private static final long SIGNAL_TIMEOUT = 300; // TODO: This should be configurable from the GUI
    CountDownLatch doneSignal = new CountDownLatch(1);

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

    private Integer totalNumberOfBackupSteps;

    private Integer totalNumberOfRestoreSteps;

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

    /**
     * @return the totalNumberOfBackupSteps
     */
    public Integer getTotalNumberOfBackupSteps() {
        return totalNumberOfBackupSteps;
    }

    /**
     * @param totalNumberOfBackupSteps the totalNumberOfBackupSteps to set
     */
    public void setTotalNumberOfBackupSteps(Integer totalNumberOfBackupSteps) {
        this.totalNumberOfBackupSteps = totalNumberOfBackupSteps;
    }

    /**
     * @return the totalNumberOfRestoreSteps
     */
    public Integer getTotalNumberOfRestoreSteps() {
        return totalNumberOfRestoreSteps;
    }

    /**
     * @param totalNumberOfRestoreSteps the totalNumberOfRestoreSteps to set
     */
    public void setTotalNumberOfRestoreSteps(Integer totalNumberOfRestoreSteps) {
        this.totalNumberOfRestoreSteps = totalNumberOfRestoreSteps;
    }

    @Override
    public void destroy() throws Exception {
        // TODO Auto-generated method stub
    }

    @Override
    public void setApplicationContext(ApplicationContext context) throws BeansException {
        Backup.context = context;
        
        try {
            AbstractJob backupJob = (AbstractJob) context.getBean(BACKUP_JOB_NAME);
            if (backupJob != null) {
                this.setTotalNumberOfBackupSteps(backupJob.getStepNames().size());
            }
            
            AbstractJob restoreJob = (AbstractJob) context.getBean(BACKUP_JOB_NAME);
            if (restoreJob != null) {
                this.setTotalNumberOfRestoreSteps(restoreJob.getStepNames().size());
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not fully configure the Backup Facade!", e);
        }
    }

    protected String getItemName(XStreamPersister xp, Class clazz) {
        return xp.getClassAliasingMapper().serializedClass(clazz);
    }

    /**
     * @return 
     * @throws IOException 
     * 
     */
    public BackupExecutionAdapter runBackupAsync(final Resource archiveFile, final boolean overwrite, final Hints params) throws IOException {
        // Check if archiveFile exists
        if(archiveFile.file().exists()) {
            if (!overwrite && FileUtils.sizeOf(archiveFile.file()) > 0) {
                // Unless the user explicitly wants to overwrite the archiveFile, throw an exception whenever it already exists
                throw new IOException("The target archive file already exists. Use 'overwrite=TRUE' if you want to overwrite it.");
            } else {
                FileUtils.forceDelete(archiveFile.file());
            }
        } else {
            // Make sure the parent path exists
            if (!archiveFile.file().getParentFile().exists()) {
                try {
                    archiveFile.file().getParentFile().mkdirs();
                } finally {
                    if (!archiveFile.file().getParentFile().exists()) {
                        throw new IOException("The path to target archive file is unreachable.");
                    }
                }
            }
        }
        
        // Initialize ZIP
        FileUtils.touch(archiveFile.file());
        
        // Write flat files into a temporary folder
        Resource tmpDir = BackupUtils.tmpDir();

        // Fill Job Parameters
        JobParametersBuilder paramsBuilder = new JobParametersBuilder();
        paramsBuilder
            .addString(PARAM_OUTPUT_FILE_PATH, BackupUtils.getArchiveURLProtocol(tmpDir) + tmpDir.path())
            .addLong(PARAM_TIME, System.currentTimeMillis());

        parseParams(params, paramsBuilder);

        JobParameters jobParameters = paramsBuilder.toJobParameters();
                
        // Send Execution Signal
        BackupExecutionAdapter backupExecution;
        try {
            while (!(getRestoreRunningExecutions().isEmpty() && getBackupRunningExecutions().isEmpty())) {
                doneSignal.await(SIGNAL_TIMEOUT, TimeUnit.SECONDS);
            }

            if(getRestoreRunningExecutions().isEmpty() && 
                    getBackupRunningExecutions().isEmpty()) {
                synchronized(jobOperator) {
                    JobExecution jobExecution = jobLauncher.run(backupJob, jobParameters);
                    backupExecution = new BackupExecutionAdapter(jobExecution, totalNumberOfBackupSteps);
                    backupExecution.setArchiveFile(archiveFile);
                    backupExecution.setOverwrite(overwrite);
                    
                    backupExecution.getOptions().add("OVERWRITE=" + overwrite);
                    for (Entry jobParam : jobParameters.toProperties().entrySet()) {
                        if (!PARAM_OUTPUT_FILE_PATH.equals(jobParam.getKey()) && 
                                !PARAM_INPUT_FILE_PATH.equals(jobParam.getKey()) && 
                                !PARAM_TIME.equals(jobParam.getKey())) {
                            backupExecution.getOptions().add(jobParam.getKey() + "=" + jobParam.getValue());
                        }
                    }
                    
                    backupExecutions.put(backupExecution.getId(), backupExecution);

                    return backupExecution;
                }
            }
            else {
                throw new IOException("Could not start a new Backup Job Execution since there are currently Running jobs.");
            }
        } catch (JobExecutionAlreadyRunningException | JobRestartException
                | JobInstanceAlreadyCompleteException | JobParametersInvalidException | InterruptedException e) {
            throw new IOException("Could not start a new Backup Job Execution: ", e);
        } finally {
            doneSignal.countDown();
        }
    }

    /**
     * @return
     * @return
     * @throws IOException
     * 
     */
    public RestoreExecutionAdapter runRestoreAsync(final Resource archiveFile, final Hints params) throws IOException {
        // Extract archive into a temporary folder
        Resource tmpDir = BackupUtils.tmpDir();
        BackupUtils.extractTo(archiveFile, tmpDir);

        // Fill Job Parameters
        JobParametersBuilder paramsBuilder = new JobParametersBuilder();
        paramsBuilder
            .addString(PARAM_INPUT_FILE_PATH, BackupUtils.getArchiveURLProtocol(tmpDir) + tmpDir.path())
            .addLong(PARAM_TIME, System.currentTimeMillis());

        parseParams(params, paramsBuilder);

        JobParameters jobParameters = paramsBuilder.toJobParameters();
        
        RestoreExecutionAdapter restoreExecution;
        try {
            while (!(getRestoreRunningExecutions().isEmpty() && getBackupRunningExecutions().isEmpty())) {
                doneSignal.await(SIGNAL_TIMEOUT, TimeUnit.SECONDS);
            }
            
            if (getRestoreRunningExecutions().isEmpty()
                    && getBackupRunningExecutions().isEmpty()) {
                synchronized (jobOperator) {
                    JobExecution jobExecution = jobLauncher.run(restoreJob, jobParameters);
                    restoreExecution = new RestoreExecutionAdapter(jobExecution, totalNumberOfRestoreSteps);
                    restoreExecution.setArchiveFile(archiveFile);
                    
                    for (Entry jobParam : jobParameters.toProperties().entrySet()) {
                        if (!PARAM_OUTPUT_FILE_PATH.equals(jobParam.getKey()) && 
                                !PARAM_INPUT_FILE_PATH.equals(jobParam.getKey()) && 
                                !PARAM_TIME.equals(jobParam.getKey())) {
                            restoreExecution.getOptions().add(jobParam.getKey() + "=" + jobParam.getValue());
                        }
                    }
                    
                    restoreExecutions.put(restoreExecution.getId(), restoreExecution);

                    return restoreExecution;
                }
            }
            else {
                throw new IOException("Could not start a new Restore Job Execution since there are currently Running jobs.");
            }
        } catch (JobExecutionAlreadyRunningException | JobRestartException
                | JobInstanceAlreadyCompleteException | JobParametersInvalidException | InterruptedException e) {
            throw new IOException("Could not start a new Restore Job Execution: ", e);
        } finally {
            doneSignal.countDown();
        }
    }

    /**
     * @param params
     * @param paramsBuilder
     */
    private void parseParams(final Hints params, JobParametersBuilder paramsBuilder) {
        if (params != null) {
            if (params.containsKey(new Hints.OptionKey(PARAM_DRY_RUN_MODE))) {
                paramsBuilder.addString(PARAM_DRY_RUN_MODE, "true");
            }
            
            if (params.containsKey(new Hints.OptionKey(PARAM_BEST_EFFORT_MODE))) {
                paramsBuilder.addString(PARAM_BEST_EFFORT_MODE, "true");
            }

            for(Entry<Object, Object> param : params.entrySet()) {
                if (param.getKey() instanceof Hints.OptionKey) {
                    final Set<String> key = ((Hints.OptionKey) param.getKey()).getOptions();
                    for (String k : key) {
                        switch (k) {
                            case PARAM_DRY_RUN_MODE:
                            case PARAM_BEST_EFFORT_MODE:
                                if (paramsBuilder.toJobParameters().getString(k) == null) {
                                    paramsBuilder.addString(k, "true");
                                }
                        }
                    }
                }
            }
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
