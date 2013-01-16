/* Copyright (c) 2012 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.wfs;

import java.util.HashMap;

import org.geoserver.config.GeoServer;
import org.geoserver.config.util.XStreamPersister;
import org.geoserver.config.util.XStreamServiceLoader;
import org.geoserver.platform.GeoServerResourceLoader;
import org.geoserver.wfs.GMLInfo.SrsNameStyle;
import org.geotools.util.Version;

/**
 * Loads and persist the {@link WFSInfo} object to and from xstream 
 * persistence.
 * 
 * @author Justin Deoliveira, The Open Planning Project
 *
 */
public class WFSXStreamLoader extends XStreamServiceLoader<WFSInfo> {

    public WFSXStreamLoader(GeoServerResourceLoader resourceLoader) {
        super(resourceLoader, "wfs");
    }

    @Override
    protected void initXStreamPersister(XStreamPersister xp, GeoServer gs) {
        super.initXStreamPersister(xp, gs);
        xp.getXStream().alias( "wfs", WFSInfo.class, WFSInfoImpl.class );
        xp.getXStream().alias( "version", WFSInfo.Version.class);
        xp.getXStream().alias( "gml", GMLInfo.class, GMLInfoImpl.class );
    }
    
    protected WFSInfo createServiceFromScratch(GeoServer gs) {
        WFSInfoImpl wfs = new WFSInfoImpl();
        wfs.setName("WFS");
        wfs.setMaxFeatures(1000000);

        //gml2
        addGml(wfs, WFSInfo.Version.V_10, GMLInfo.SrsNameStyle.XML, true);
        
        //gml3
        addGml(wfs, WFSInfo.Version.V_11, GMLInfo.SrsNameStyle.URN, false);
        
        //gml3.2
        addGml(wfs, WFSInfo.Version.V_20, SrsNameStyle.URN2, false);
        return wfs;
    }

    public Class<WFSInfo> getServiceClass() {
        return WFSInfo.class;
    }
    
    @Override
    protected WFSInfo initialize(WFSInfo service) {
        super.initialize(service);
        if ( service.getVersions().isEmpty() ) {
            service.getVersions().add(WFSInfo.Version.V_10.getVersion());
            service.getVersions().add(WFSInfo.Version.V_11.getVersion());
        }

        if (!service.getVersions().contains(WFSInfo.Version.V_20.getVersion())) {
            service.getVersions().add(WFSInfo.Version.V_20.getVersion());
        }
        
        //set the defaults for GMLInfo if they are not set
        if(service.getGML() == null) {
            ((WFSInfoImpl) service).setGML(new HashMap<WFSInfo.Version, GMLInfo>());           
        }
        GMLInfo gml = service.getGML().get(WFSInfo.Version.V_10);
        if(gml == null) {
            addGml(service, WFSInfo.Version.V_10, SrsNameStyle.URL, false);
        } else if (gml.getOverrideGMLAttributes() == null) {
            gml.setOverrideGMLAttributes(true);
        }
        gml = service.getGML().get(WFSInfo.Version.V_11);
        if(gml == null) {
            addGml(service, WFSInfo.Version.V_11, SrsNameStyle.URN, false);
        } else if (gml.getOverrideGMLAttributes() == null) {
            gml.setOverrideGMLAttributes(false);
        }
        gml = service.getGML().get(WFSInfo.Version.V_20);
        if (gml == null) {
            addGml(service, WFSInfo.Version.V_20, SrsNameStyle.URN2, false);
        }
        return service;
    }

    void addGml(WFSInfo info, WFSInfo.Version ver, SrsNameStyle srs, boolean overrideGmlAtts) {
        GMLInfo gml = new GMLInfoImpl();
        gml.setSrsNameStyle(srs);
        gml.setOverrideGMLAttributes(overrideGmlAtts);
        info.getGML().put(ver, gml);
    }
}
