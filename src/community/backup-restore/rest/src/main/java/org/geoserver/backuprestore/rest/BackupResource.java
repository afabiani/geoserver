/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2016 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.backuprestore.rest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.geoserver.backuprestore.Backup;
import org.geoserver.backuprestore.BackupExecutionAdapter;
import org.geoserver.backuprestore.rest.format.BackupJSONWriter;
import org.geoserver.rest.PageInfo;
import org.geoserver.rest.RestletException;
import org.geoserver.rest.format.DataFormat;
import org.geoserver.rest.format.StreamDataFormat;
import org.restlet.data.Form;
import org.restlet.data.MediaType;
import org.restlet.data.Request;
import org.restlet.data.Response;
import org.restlet.data.Status;

/**
 * REST resource for 
 * 
 * <pre>/br/backup[/&lt;backupId&gt;]</pre>
 * 
 * @author Alessio Fabiani, GeoSolutions
 *
 */
public class BackupResource  extends BaseResource {

    public BackupResource(Backup backupFacade) {
        super(backupFacade);
    }

    @Override
    protected List<DataFormat> createSupportedFormats(Request arg0, Response arg1) {
        return (List) Arrays.asList(new BackupJSONFormat(MediaType.APPLICATION_JSON),
                new BackupJSONFormat(MediaType.TEXT_HTML));
    }

    @Override
    public boolean allowPost() {
        return true;
    }
    
    @Override
    public boolean allowPut() {
        return false;
    }
    
    @Override
    public void handleGet() {
        DataFormat formatGet = getFormatGet();
        if (formatGet == null) {
            formatGet = new BackupJSONFormat(MediaType.APPLICATION_JSON);
        }
        Object lookupContext = lookupContext(true, false);
        if (lookupContext == null) {
            // this means a specific lookup failed
            getResponse().setStatus(Status.CLIENT_ERROR_NOT_FOUND);
        } else {
            getResponse().setEntity(formatGet.toRepresentation(lookupContext));
        }
    }
    
    @Override
    public void handlePost() {
        Object obj = lookupContext(true, true);
        BackupExecutionAdapter execution = null;
        if (obj instanceof BackupExecutionAdapter) {
            // TODO: restart an existing execution
            /*try {
                restartImport((BackupExecutionAdapter) obj);
            } catch (Throwable t) {
                if (t instanceof ValidationException) {
                    throw new RestletException(t.getMessage(), Status.CLIENT_ERROR_BAD_REQUEST, t);
                } else {
                    throw new RestletException("Error occured executing import", Status.SERVER_ERROR_INTERNAL, t);
                }
            }*/
        }
        else {
            execution = runBackup();
        }
        if (execution != null) {
            // TODO 
        }
    }
    
    /**
     * 
     * @return
     */
    private BackupExecutionAdapter runBackup() {
        BackupExecutionAdapter execution = null;
        
        try {
            Form query = getRequest().getResourceRef().getQueryAsForm();
    
            if (MediaType.APPLICATION_JSON.equals(getRequest().getEntity().getMediaType())) {
                BackupExecutionAdapter newExecution = (BackupExecutionAdapter) getFormatPostOrPut().toObject(getRequest().getEntity());
    
                // TODO: Parse parameters
                execution = backupFacade.runBackupAsync(null);
    
                getResponse().redirectSeeOther(getPageInfo().rootURI("/br/backup/"+execution.getId()));
                getResponse().setEntity(getFormatGet().toRepresentation(execution));
                getResponse().setStatus(Status.SUCCESS_CREATED);
            } else {
                throw new IllegalArgumentException("Unknown Content-Type: " + getRequest().getEntity().getMediaType());
            }
        } catch (IllegalArgumentException iae) {
            throw new RestletException("Unable to create import", Status.CLIENT_ERROR_BAD_REQUEST, iae);
        } catch (Exception e) {
            throw new RestletException("Unable to create import", Status.SERVER_ERROR_INTERNAL, e);
        }
        
        return execution;
    }

    class BackupJSONFormat extends StreamDataFormat {

        public BackupJSONFormat(MediaType type) {
            super(type);
        }

        @Override
        protected Object read(InputStream in) throws IOException {
            return newReader(in).execution();
        }

        @Override
        protected void write(Object object, OutputStream out) throws IOException {
            
            PageInfo pageInfo = getPageInfo();
            // @hack lop off query if there is one or resulting URIs look silly
            int queryIdx = pageInfo.getPagePath().indexOf('?');
            if (queryIdx > 0) {
                pageInfo.setPagePath(pageInfo.getPagePath().substring(0, queryIdx));
            }

            BackupJSONWriter json = newWriter(out);
            if (object instanceof BackupExecutionAdapter) {
                json.execution((BackupExecutionAdapter) object, true, expand(1));
            }
            else {
                json.executions((Iterator<BackupExecutionAdapter>) object, expand(0));
            }
        }
    }
    
    Object lookupContext(boolean allowAll, boolean mustExist) {
        String i = getAttribute("backupId");
        if (i != null) {
            BackupExecutionAdapter backupExecution = null;
            try {
                backupExecution = backupFacade.getBackupExecutions().get(Long.parseLong(i));
            } catch (NumberFormatException e) {
            }
            if (backupExecution == null && mustExist) {
                throw new RestletException("No such backup execution: " + i, Status.CLIENT_ERROR_NOT_FOUND);
            }
            return backupExecution;
        }
        else {
            if (allowAll) {
                return backupFacade.getBackupExecutions().entrySet().iterator();
            }
            throw new RestletException("No backup execution specified", Status.CLIENT_ERROR_BAD_REQUEST);
        }
    }
    
}
