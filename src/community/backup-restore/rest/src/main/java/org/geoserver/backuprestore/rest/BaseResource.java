/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.backuprestore.rest;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.DateFormat;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.geoserver.backuprestore.AbstractExecutionAdapter;
import org.geoserver.backuprestore.Backup;
import org.geoserver.backuprestore.BackupExecutionAdapter;
import org.geoserver.backuprestore.RestoreExecutionAdapter;
import org.geoserver.catalog.CatalogException;
import org.geoserver.platform.resource.Files;
import org.geoserver.platform.resource.Resource;
import org.geoserver.rest.AbstractResource;
import org.geotools.factory.Hints;
import org.geotools.util.logging.Logging;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobParameter;
import org.springframework.batch.core.StepExecution;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.converters.basic.AbstractSingleValueConverter;
import com.thoughtworks.xstream.converters.collections.CollectionConverter;
import com.thoughtworks.xstream.converters.reflection.ReflectionConverter;
import com.thoughtworks.xstream.converters.reflection.ReflectionProvider;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import com.thoughtworks.xstream.mapper.ClassAliasingMapper;
import com.thoughtworks.xstream.mapper.Mapper;

/**
 * Abstract Class representing a Backup REST Resource. 
 * 
 * It contains a the {@link Backup} backupFacade reference and utility methods to read/write the
 * resources to/from JSON.
 * 
 * Based on Importer {@link BaseResource}
 * 
 * @author Justin Deoliveira, OpenGeo
 * @author Alessio Fabiani, GeoSolutions
 */
public abstract class BaseResource extends AbstractResource {

    static Logger LOGGER = Logging.getLogger(BaseResource.class);

    private Backup backupFacade;

    public BaseResource(Backup backupFacade) {
        this.backupFacade = backupFacade;
    }

    /**
     * @return the backupFacade
     */
    public Backup getBackupFacade() {
        return backupFacade;
    }

    /**
     * @param backupFacade the backupFacade to set
     */
    public void setBackupFacade(Backup backupFacade) {
        this.backupFacade = backupFacade;
    }

    protected int expand(int def) {
        String ex = getRequest().getResourceRef().getQueryAsForm().getFirstValue("expand");
        if (ex == null) {
            return def;
        }

        try {
            return "self".equalsIgnoreCase(ex) ? 1
                    : "all".equalsIgnoreCase(ex) ? Integer.MAX_VALUE
                            : "none".equalsIgnoreCase(ex) ? 0 : Integer.parseInt(ex);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    protected  Hints asParams(List<String> options) {
        Hints hints = new Hints(new HashMap(2));

        if (options != null) {
            for (String option : options) {
                if (option.startsWith(Backup.PARAM_DRY_RUN_MODE)) {
                    if (option.indexOf("=")>0) {
                        if (!option.toLowerCase().endsWith("true")) {
                            continue;
                        }
                    }
                    hints.add(new Hints(new Hints.OptionKey(Backup.PARAM_DRY_RUN_MODE), Backup.PARAM_DRY_RUN_MODE));
                }

                if (option.startsWith(Backup.PARAM_BEST_EFFORT_MODE)) {
                    if (option.indexOf("=")>0) {
                        if (!option.toLowerCase().endsWith("true")) {
                            continue;
                        }
                    }
                    hints.add(new Hints(new Hints.OptionKey(Backup.PARAM_BEST_EFFORT_MODE), Backup.PARAM_BEST_EFFORT_MODE));
                }
            }
        }
        
        return hints;
    }
    
    /**
     * @param xStream
     */
    protected void intializeXStreamContext(XStream xStream) {
        //Adapter
        xStream.alias("backup", BackupExecutionAdapter.class);
        xStream.alias("restore", RestoreExecutionAdapter.class);
        
        // setup white list of accepted classes
        xStream.allowTypes(new String[] { "org.geoserver.platform.resource.Files$ResourceAdaptor" });
        xStream.allowTypesByWildcard(new String[] { "org.geoserver.backuprestore.**" });
        
        // Configure aliases and converters
        xStream.omitField(RestoreExecutionAdapter.class, "restoreCatalog");

        Class synchronizedListType = Collections.synchronizedList(Collections.EMPTY_LIST).getClass();
        xStream.alias("synchList", synchronizedListType);
        
        ClassAliasingMapper optionsMapper = new ClassAliasingMapper(xStream.getMapper());
        optionsMapper.addClassAlias("option", String.class);        
        xStream.registerLocalConverter(AbstractExecutionAdapter.class, "options", new CollectionConverter(optionsMapper) {
            
            @Override
            public boolean canConvert(Class type) {
                return Collection.class.isAssignableFrom(type);
            }
            
        });
        
        ClassAliasingMapper warningsMapper = new ClassAliasingMapper(xStream.getMapper());
        warningsMapper.addClassAlias(Level.WARNING.getName(), RuntimeException.class);
        warningsMapper.addClassAlias(Level.WARNING.getName(), CatalogException.class);
        xStream.registerLocalConverter(AbstractExecutionAdapter.class, "warningsList", new CollectionConverter(warningsMapper) {
            
            @Override
            public boolean canConvert(Class type) {
                return Collection.class.isAssignableFrom(type);
            }
            
        });
        
        Class resourceAdaptorType = Files.asResource(new File("/")).getClass();
        xStream.alias("resource", resourceAdaptorType);
        xStream.registerLocalConverter(AbstractExecutionAdapter.class, "archiveFile", new ArchiveFileResourceConverter());

        //Delegate
        xStream.aliasAttribute(AbstractExecutionAdapter.class, "delegate", "execution");
        xStream.omitField(JobExecution.class, "version");
        xStream.omitField(JobExecution.class, "jobInstance");
        xStream.omitField(JobExecution.class, "jobId");
        xStream.omitField(JobExecution.class, "jobParameters");
        xStream.omitField(JobExecution.class, "executionContext");
        
        xStream.registerLocalConverter(AbstractExecutionAdapter.class, "delegate", 
                new JobExecutionConverter(xStream.getMapper(), xStream.getReflectionProvider(), this.backupFacade));
        
        ClassAliasingMapper stepExecutionsMapper = new ClassAliasingMapper(xStream.getMapper());
        stepExecutionsMapper.addClassAlias("step", StepExecution.class);
        xStream.registerLocalConverter(JobExecution.class, "stepExecutions", new CollectionConverter(stepExecutionsMapper) {
            
            @Override
            public boolean canConvert(Class type) {
                return CopyOnWriteArraySet.class.isAssignableFrom(type);
            }

            @Override
            public void marshal(Object obj, HierarchicalStreamWriter writer,
                    MarshallingContext ctx) {
                CopyOnWriteArraySet execs = (CopyOnWriteArraySet) obj;
                Iterator iterator = execs.iterator();
                
                while (iterator.hasNext()) {
                    StepExecution exec = (StepExecution) iterator.next();
                    
                    // Step Node - START
                    writer.startNode("step");
                    
                    writer.startNode("name");
                    writer.setValue(exec.getStepName());
                    writer.endNode();

                    writer.startNode("status");
                    writer.setValue(exec.getStatus().name());
                    writer.endNode();

                    writer.startNode("exitStatus");
                    writer.startNode("exitCode");
                    writer.setValue(exec.getExitStatus().getExitCode());
                    writer.endNode();
                    writer.startNode("exitDescription");
                    writer.setValue(exec.getExitStatus().getExitDescription());
                    writer.endNode();
                    writer.endNode();
                    
                    if (exec.getStartTime() != null) {
                        writer.startNode("startTime");
                        writer.setValue(DateFormat.getInstance().format(exec.getStartTime()));
                        writer.endNode();
                    }
                    
                    if (exec.getEndTime() != null) {
                        writer.startNode("endTime");
                        writer.setValue(DateFormat.getInstance().format(exec.getEndTime()));
                        writer.endNode();
                    }
                    
                    if (exec.getLastUpdated() != null) {
                        writer.startNode("lastUpdated");
                        writer.setValue(DateFormat.getInstance().format(exec.getLastUpdated()));
                        writer.endNode();
                    }
                    
                    writer.startNode("parameters");
                    for (Entry param : exec.getJobParameters().getParameters().entrySet()) {
                        writer.startNode((String) param.getKey());
                        writer.setValue(((JobParameter) param.getValue()).getValue().toString());
                        writer.endNode();
                    }
                    writer.endNode();
                    
                    writer.startNode("readCount");
                    writer.setValue(String.valueOf(exec.getReadCount()));
                    writer.endNode();
                
                    writer.startNode("writeCount");
                    writer.setValue(String.valueOf(exec.getWriteCount()));
                    writer.endNode();
                    
                    writer.startNode("failureExceptions");
                    for (Throwable ex : exec.getFailureExceptions()) {
                        writer.startNode(Level.SEVERE.getName());
                        
                        StringBuilder buf = new StringBuilder();
                        while (ex != null) {
                            if (buf.length() > 0) {
                                buf.append('\n');
                            }
                            if (ex.getMessage() != null) {
                                buf.append(ex.getMessage());
                                
                                StringWriter errors = new StringWriter();
                                ex.printStackTrace(new PrintWriter(errors));
                                buf.append('\n').append(errors.toString());
                            }
                            ex = ex.getCause();
                        }
                        
                        writer.setValue(buf.toString());
                        writer.endNode();
                    }
                    writer.endNode();
                    
                    // Step Node - END
                    writer.endNode();
                }
            }
            
        });
        
    }
    
    /**
     * 
     * @author Alessio Fabiani, GeoSolutions S.A.S.
     *
     */
    static public class ArchiveFileResourceConverter extends AbstractSingleValueConverter {
        
        @Override
        public boolean canConvert(Class type) {
            return Resource.class.isAssignableFrom(type);
        }

        @Override
        public String toString(Object obj) {
            return ((Resource)obj).path();
        }

        @Override
        public Object fromString(String str) {
            return Files.asResource(new File(str));
        }
    }
    
    /**
     * 
     * @author Alessio Fabiani, GeoSolutions S.A.S.
     *
     */
    static public class JobExecutionConverter extends ReflectionConverter {
        
        private Backup backupFacade;

        JobExecutionConverter(Mapper mapper,
                ReflectionProvider reflectionProvider, Backup backupFacade) {
            super(mapper, reflectionProvider);
            this.backupFacade = backupFacade;
        }

        @Override
        public void marshal(Object obj, HierarchicalStreamWriter writer,
                MarshallingContext context) {
            super.marshal(obj,writer,context);

            JobExecution dl = (JobExecution) obj;
            Integer numSteps = 0;
            if (dl.getJobInstance().getJobName().equals(Backup.BACKUP_JOB_NAME)) {
                numSteps = backupFacade.getTotalNumberOfBackupSteps();
            } else if (dl.getJobInstance().getJobName().equals(Backup.RESTORE_JOB_NAME)) {
                numSteps = backupFacade.getTotalNumberOfRestoreSteps();
            }
            
            writer.startNode("progress");
            final StringBuffer progress = new StringBuffer();
            progress.append(dl.getStepExecutions().size()).append("/").append(numSteps);
            writer.setValue(progress.toString());
            writer.endNode();
        }

        @Override
        public Object unmarshal(HierarchicalStreamReader reader,
                UnmarshallingContext context) {
            return super.unmarshal(reader,context);
        }

        @SuppressWarnings("unchecked")
        @Override
        public boolean canConvert(Class clazz) {
            return clazz.equals(JobExecution.class);
        }
        
    }
}
