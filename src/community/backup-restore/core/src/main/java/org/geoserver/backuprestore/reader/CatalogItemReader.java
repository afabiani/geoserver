/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.backuprestore.reader;

import java.util.Arrays;

import org.geoserver.backuprestore.Backup;
import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.util.CloseableIterator;
import org.geoserver.config.util.XStreamPersisterFactory;
import org.opengis.filter.Filter;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.item.ItemReader;
import org.springframework.core.io.Resource;

/**
 * Concrete Spring Batch {@link ItemReader}.
 * 
 * Reads resource items from in memory {@link Catalog}.
 * 
 * @author Alessio Fabiani, GeoSolutions
 *
 */
public class CatalogItemReader<T> extends CatalogReader<T> {

    CloseableIterator<T> catalogIterator;
    
    public CatalogItemReader(Class<T> clazz, Backup backupFacade,
            XStreamPersisterFactory xStreamPersisterFactory) {
        super(clazz, backupFacade, xStreamPersisterFactory);
    }
    
    @SuppressWarnings("unchecked")
    protected void beforeStep(StepExecution stepExecution) {
        this.catalogIterator = (CloseableIterator<T>) catalog.list(this.clazz, Filter.INCLUDE);
    }
    
    @Override
    public T read() {
        try {
            if (catalogIterator.hasNext()) {
                return (T) catalogIterator.next();
            }
        } catch (Exception e) {
            if(!isBestEffort()) {
                getCurrentJobExecution().addFailureExceptions(Arrays.asList(e));
                throw e;
            } else {
                getCurrentJobExecution().
                    addWarningExceptions(Arrays.asList(e));
            }
        }
        
        return null;
    }

    @Override
    public void setResource(Resource resource) {
        // TODO Auto-generated method stub
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        // TODO Auto-generated method stub
    }

    @Override
    protected T doRead() throws Exception {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    protected void doOpen() throws Exception {
        // TODO Auto-generated method stub
    }

    @Override
    protected void doClose() throws Exception {
        // TODO Auto-generated method stub
    }

}
