/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2016 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.backuprestore;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.geoserver.catalog.CascadeDeleteVisitor;
import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.CoverageInfo;
import org.geoserver.catalog.DataStoreInfo;
import org.geoserver.catalog.FeatureTypeInfo;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.batch.core.BatchStatus;

/**
 * 
 * @author Alessio Fabiani, GeoSolutions
 *
 */
public class BackupTest extends BackupRestoreTestSupport {

    DataStoreInfo store;

    @Before
    public void setupStore() {
        Catalog cat = getCatalog();

        store = cat.getFactory().createDataStore();
        store.setWorkspace(cat.getDefaultWorkspace());
        store.setName("spearfish");
        store.setType("H2");

        Map params = new HashMap();
        params.put("database", getTestData().getDataDirectoryRoot().getPath() + "/spearfish");
        params.put("dbtype", "h2");
        store.getConnectionParameters().putAll(params);
        store.setEnabled(true);
        cat.add(store);
    }

    @After
    public void dropStore() {
        Catalog cat = getCatalog();
        CascadeDeleteVisitor visitor = new CascadeDeleteVisitor(cat);
        store.accept(visitor);
    }

    @Test
    public void testRunSpringBatchBackupJob() throws Exception {
        backupFacade.runBackupAsync(null);

        assertNotNull(backupFacade.getBackupExecutions());
        assertTrue(!backupFacade.getBackupExecutions().isEmpty());

        BackupExecutionAdapter backupExecution = null;
        final Iterator<BackupExecutionAdapter> iterator = backupFacade.getBackupExecutions()
                .values().iterator();
        while (iterator.hasNext()) {
            backupExecution = iterator.next();
        }

        assertNotNull(backupExecution);

        while (backupExecution.isRunning()) {
            Thread.sleep(100);
        }

        assertTrue(backupExecution.getStatus() == BatchStatus.COMPLETED);
    }

    @Test
    public void testTryToRunMultipleSpringBatchBackupJobs() throws Exception {
        backupFacade.runBackupAsync(null);
        backupFacade.runBackupAsync(null);
        backupFacade.runBackupAsync(null);

        assertNotNull(backupFacade.getBackupExecutions());
        assertTrue(!backupFacade.getBackupExecutions().isEmpty());
        assertTrue(backupFacade.getBackupExecutions().size() == 1);

        BackupExecutionAdapter backupExecution = null;
        final Iterator<BackupExecutionAdapter> iterator = backupFacade.getBackupExecutions()
                .values().iterator();
        while (iterator.hasNext()) {
            backupExecution = iterator.next();
        }

        assertNotNull(backupExecution);

        while (backupExecution.isRunning()) {
            Thread.sleep(100);
        }

        assertTrue(backupExecution.getStatus() == BatchStatus.COMPLETED);
    }

    @Test
    public void testRunSpringBatchRestoreJob() throws Exception {
        backupFacade.runRestoreAsync(file("bk_test_simple.zip"));

        assertNotNull(backupFacade.getRestoreExecutions());
        assertTrue(!backupFacade.getRestoreExecutions().isEmpty());

        RestoreExecutionAdapter restoreExecution = null;
        final Iterator<RestoreExecutionAdapter> iterator = backupFacade.getRestoreExecutions()
                .values().iterator();
        while (iterator.hasNext()) {
            restoreExecution = iterator.next();
        }

        assertNotNull(restoreExecution);

        Thread.sleep(100);

        final Catalog restoreCatalog = restoreExecution.getRestoreCatalog();
        assertNotNull(restoreCatalog);

        while (restoreExecution.isRunning()) {
            Thread.sleep(100);
        }

        assertTrue(restoreExecution.getStatus() == BatchStatus.COMPLETED);

        assertTrue(restoreCatalog.getWorkspaces().size() == restoreCatalog.getNamespaces().size());

        assertTrue(restoreCatalog.getDataStores().size() == 1);
        assertTrue(restoreCatalog.getResources(FeatureTypeInfo.class).size() == 0);
        assertTrue(restoreCatalog.getResources(CoverageInfo.class).size() == 0);
        assertTrue(restoreCatalog.getStyles().size() == 6);
        assertTrue(restoreCatalog.getLayers().size() == 0);
        assertTrue(restoreCatalog.getLayerGroups().size() == 0);
    }
}
