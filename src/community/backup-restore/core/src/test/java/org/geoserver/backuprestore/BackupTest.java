/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2016 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.backuprestore;

import static org.easymock.EasyMock.expect;
import static org.easymock.classextension.EasyMock.createNiceMock;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.logging.Level;

import org.geoserver.backuprestore.utils.BackupUtils;
import org.geoserver.backuprestore.writer.ResourceInfoAdditionalResourceWriter;
import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.CoverageInfo;
import org.geoserver.catalog.FeatureTypeInfo;
import org.geoserver.config.GeoServerDataDirectory;
import org.geoserver.platform.resource.Files;
import org.geoserver.platform.resource.Paths;
import org.geoserver.platform.resource.Resource;
import org.geoserver.platform.resource.Resources;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.batch.core.BatchStatus;

/**
 * 
 * @author Alessio Fabiani, GeoSolutions
 *
 */
public class BackupTest extends BackupRestoreTestSupport {

    static File root;

    @BeforeClass
    public static void createTmpDir() throws Exception {
        root = File.createTempFile("template", "tmp", new File("target"));
        root.delete();
        root.mkdir();
    }

    GeoServerDataDirectory createDataDirectoryMock() {
        GeoServerDataDirectory dd = createNiceMock(GeoServerDataDirectory.class);
        expect(dd.root()).andReturn(root).anyTimes();
        return dd;
    }

    @Test
    public void testRunSpringBatchBackupJob() throws Exception {
        BackupExecutionAdapter backupExecution = backupFacade.runBackupAsync(
                Files.asResource(File.createTempFile("testRunSpringBatchBackupJob", ".zip")), true);

        // Wait a bit
        Thread.sleep(100);

        assertNotNull(backupFacade.getBackupExecutions());
        assertTrue(!backupFacade.getBackupExecutions().isEmpty());
        assertNotNull(backupExecution);

        while (backupExecution.getStatus() != BatchStatus.COMPLETED) {
            Thread.sleep(100);

            if (backupExecution.getStatus() == BatchStatus.ABANDONED
                    || backupExecution.getStatus() == BatchStatus.FAILED) {

                for (Throwable exception : backupExecution.getAllFailureExceptions()) {
                    LOGGER.log(Level.INFO, "ERROR: " + exception.getLocalizedMessage(), exception);
                    exception.printStackTrace();
                }
                break;
            }
        }

        assertTrue(backupExecution.getStatus() == BatchStatus.COMPLETED);
    }

    @Test
    public void testTryToRunMultipleSpringBatchBackupJobs() throws Exception {
        backupFacade.runBackupAsync(
                Files.asResource(File.createTempFile("testRunSpringBatchBackupJob", ".zip")), true);
        try {
            backupFacade.runBackupAsync(
                    Files.asResource(File.createTempFile("testRunSpringBatchBackupJob", ".zip")),
                    true);
        } catch (IOException e) {
            assertEquals(e.getMessage(),
                    "Could not start a new Backup Job Execution since there are currently Running jobs.");
        }

        // Wait a bit
        Thread.sleep(100);

        assertNotNull(backupFacade.getBackupExecutions());
        assertTrue(!backupFacade.getBackupExecutions().isEmpty());
        assertTrue(backupFacade.getBackupRunningExecutions().size() == 1);

        BackupExecutionAdapter backupExecution = null;
        final Iterator<BackupExecutionAdapter> iterator = backupFacade.getBackupExecutions()
                .values().iterator();
        while (iterator.hasNext()) {
            backupExecution = iterator.next();
        }

        assertNotNull(backupExecution);

        while (backupExecution.getStatus() != BatchStatus.COMPLETED) {
            Thread.sleep(100);

            if (backupExecution.getStatus() == BatchStatus.ABANDONED
                    || backupExecution.getStatus() == BatchStatus.FAILED) {
                LOGGER.severe("backupExecution.getStatus() == " + (backupExecution.getStatus()));

                for (Throwable exception : backupExecution.getAllFailureExceptions()) {
                    LOGGER.log(Level.INFO, "ERROR: " + exception.getLocalizedMessage(), exception);
                    exception.printStackTrace();
                }
                break;
            }
        }

        assertTrue(backupExecution.getStatus() == BatchStatus.COMPLETED);
    }

    @Test
    public void testRunSpringBatchRestoreJob() throws Exception {
        RestoreExecutionAdapter restoreExecution = backupFacade
                .runRestoreAsync(file("bk_test_simple.zip"));

        // Wait a bit
        Thread.sleep(100);

        assertNotNull(backupFacade.getRestoreExecutions());
        assertTrue(!backupFacade.getRestoreExecutions().isEmpty());

        assertNotNull(restoreExecution);

        Thread.sleep(100);

        final Catalog restoreCatalog = restoreExecution.getRestoreCatalog();
        assertNotNull(restoreCatalog);

        while (restoreExecution.getStatus() != BatchStatus.COMPLETED) {
            Thread.sleep(100);

            if (restoreExecution.getStatus() == BatchStatus.ABANDONED
                    || restoreExecution.getStatus() == BatchStatus.FAILED) {

                for (Throwable exception : restoreExecution.getAllFailureExceptions()) {
                    LOGGER.log(Level.INFO, "ERROR: " + exception.getLocalizedMessage(), exception);
                    exception.printStackTrace();
                }
                break;
            }
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

    @Test
    public void testResourceInfoAdditionalResourceWriter() throws IOException {
        Catalog cat = getCatalog();

        GeoServerDataDirectory dd = backupFacade.getGeoServerDataDirectory();
        GeoServerDataDirectory td = new GeoServerDataDirectory(root);

        Resource srcTemplatesDir = BackupUtils.dir(dd.get(Paths.BASE), "templates");
        File srcTitleFtl = Resources
                .createNewFile(Files.asResource(new File(srcTemplatesDir.dir(), "title.ftl")));
        File srcHeaderFtl = Resources.createNewFile(Files.asResource(new File(
                Paths.toFile(dd.get(Paths.BASE).dir(), Paths.path("workspaces", "gs", "foo", "t1")),
                "header.ftl")));
        File srcFakeFtl = Resources.createNewFile(Files.asResource(new File(
                Paths.toFile(dd.get(Paths.BASE).dir(), Paths.path("workspaces", "gs", "foo", "t1")),
                "fake.ftl")));

        assertTrue(Resources.exists(Files.asResource(srcTitleFtl)));
        assertTrue(Resources.exists(Files.asResource(srcHeaderFtl)));
        assertTrue(Resources.exists(Files.asResource(srcFakeFtl)));

        FeatureTypeInfo ft = cat.getFeatureTypeByName("t1");

        ResourceInfoAdditionalResourceWriter riarw = new ResourceInfoAdditionalResourceWriter();
        riarw.writeAdditionalResources(backupFacade, td.get(Paths.BASE), ft);

        Resource trgTemplatesDir = BackupUtils.dir(td.get(Paths.BASE), "templates");

        assertTrue(Resources.exists(trgTemplatesDir));

        Resource trgTitleFtl = Files.asResource(new File(trgTemplatesDir.dir(), "title.ftl"));
        Resource trgHeaderFtl = Files.asResource(new File(
                Paths.toFile(td.get(Paths.BASE).dir(), Paths.path("workspaces", "gs", "foo", "t1")),
                "header.ftl"));
        Resource trgFakeFtl = Files.asResource(new File(
                Paths.toFile(td.get(Paths.BASE).dir(), Paths.path("workspaces", "gs", "foo", "t1")),
                "fake.ftl"));

        assertTrue(Resources.exists(trgTitleFtl));
        assertTrue(Resources.exists(trgHeaderFtl));
        assertTrue(!Resources.exists(trgFakeFtl));
    }
}
