/* Copyright (c) 2001 - 2013 OpenPlans - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.config;

import static org.junit.Assert.*;

import org.geoserver.test.GeoServerSystemTestSupport;
import org.junit.Test;

public class UpdateSequenceListenerTest extends GeoServerSystemTestSupport {

    @Test
    public void testCatalogUpdates() {
        long updateSequence = getGeoServer().getGlobal().getUpdateSequence();
        
        // remove one layer
        getCatalog().remove(getCatalog().getLayers().get(0));
        
        long newUpdateSequence = getGeoServer().getGlobal().getUpdateSequence();
        assertTrue(newUpdateSequence > updateSequence);
    }
    
    @Test
    public void testServiceUpdates() {
        GeoServerInfo global = getGeoServer().getGlobal();
        long updateSequence = global.getUpdateSequence();
        
        // change a flag in the config
        global.setVerbose(true);
        getGeoServer().save(global);
        
        
        long newUpdateSequence = getGeoServer().getGlobal().getUpdateSequence();
        assertTrue(newUpdateSequence > updateSequence);
    }
}
