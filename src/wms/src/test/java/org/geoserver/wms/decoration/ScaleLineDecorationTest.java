package org.geoserver.wms.decoration;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

import javax.imageio.ImageIO;

import org.junit.Test;

public class ScaleLineDecorationTest extends DecorationTestSupport {

    @Test
    public void testTransparency() throws Exception {
        ScaleLineDecoration d = new ScaleLineDecoration();
        BufferedImage bi = paintOnImage(d);
        
        ImageIO.write(bi, "PNG", new File("/tmp/test.png"));

        assertPixel(bi, 180, 160, Color.WHITE);
        
        // setup for transparent background
        Map<String, String> options = new HashMap<String, String>();
        options.put("transparent", "true");
        d.loadOptions(options);

        // check we get a transparent background in the same location
        BufferedImage bi2 = paintOnImage(d);
        // ImageIO.write(bi2, "PNG", new File("/tmp/test.png"));
        assertPixel(bi2, 180, 160, new Color(0, 0, 0, 0));
    }

    private BufferedImage paintOnImage(ScaleLineDecoration d) throws Exception {
        BufferedImage bi = new BufferedImage(300, 300, BufferedImage.TYPE_4BYTE_ABGR);
        Graphics2D g2d = bi.createGraphics();
        d.paint(g2d, new Rectangle(300, 300), createMapContent(300));
        g2d.dispose();
        return bi;
    }
}
