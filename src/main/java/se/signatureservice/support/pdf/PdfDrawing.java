/************************************************************************
 *                                                                       *
 *  Signature Service - Support Service Library                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.pdf;

import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer.DefaultImageDrawerUtils;
import eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer.JavaDSSFontMetrics;
import eu.europa.esig.dss.pdf.visible.*;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.image.LosslessFactory;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Logic for drawing a visible signature, as specified by the SignatureImageParameters.
 * Inspired by and partly copied from the EU DSS library, in order to render the same visual contents of a signature,
 * but without the signature objects, in case the caller wants a signature-free PDF copy.
 *
 * @author Fredrik
 */
public class PdfDrawing {

    /**
     * Method to draw the visual signature, according to the imageParameters.
     *
     * @param document The original PDF document.
     * @param imageParameters SignatureImageParameters specifying what to draw.
     * @return The bytes of the modified PDF document.
     */
    public static byte[] draw(InMemoryDocument document, SignatureImageParameters imageParameters) throws IOException {
        try (var pdDocument = Loader.loadPDF(document.getBytes()); var bout = new ByteArrayOutputStream()) {
            var result = drawInternal(pdDocument, imageParameters);
            if (result.getSignatureDictionaries().isEmpty()) {
                result.save(bout);
            } else {
                // Save the PDF as an incremental update, preserving the existing signature objects
                result.saveIncremental(bout);
            }
            return bout.toByteArray();
        }
    }

    private static PDDocument drawInternal(PDDocument document, SignatureImageParameters parameters) throws IOException {
        SignatureFieldDimensionAndPosition dimensionAndPosition = buildSignatureFieldBox(parameters, document);

        // Build image
        var bufferedImage = buildImage(parameters, dimensionAndPosition);

        // Draw image
        int pageNumber = parameters.getFieldParameters().getPage() - ImageUtils.DEFAULT_FIRST_PAGE;
        PDPage page = document.getPage(pageNumber);

        PDImageXObject pdImage = LosslessFactory.createFromImage(document, bufferedImage);

        //AnnotationBox pageBox = getPageAnnotationBox(page);
        AnnotationBox annotationBox = dimensionAndPosition.getAnnotationBox();

        float x = annotationBox.getMinX();
        float y =  annotationBox.getMinY();      //pageBox.getHeight() - annotationBox.getMaxY();
        float width = annotationBox.getWidth();
        float height = annotationBox.getHeight();

        try (PDPageContentStream cs = new PDPageContentStream(document, page,
                PDPageContentStream.AppendMode.APPEND, true, true)) {
            cs.drawImage(pdImage, x, y, width, height);
        }

        return document;
    }

    private static BufferedImage buildImage(SignatureImageParameters parameters, SignatureFieldDimensionAndPosition dimensionAndPosition) {
        BufferedImage image = null;
        BufferedImage textImage = null;

        if (parameters.getImage() != null) {
            image = DefaultImageDrawerUtils.toBufferedImage(parameters.getImage());
        }
        if (parameters.getTextParameters() != null && !parameters.getTextParameters().isEmpty()) {
            DSSFont dssFont = parameters.getTextParameters().getFont();
            Font javaFont = dssFont.getJavaFont();
            float properSize = dssFont.getSize() * ImageUtils.getScaleFactor(parameters.getZoom());
            Font properFont = javaFont.deriveFont(properSize);

            JavaDSSFontMetrics fontMetrics = new JavaDSSFontMetrics(properFont);
            textImage = DefaultImageDrawerUtils.createTextImage(parameters, dimensionAndPosition, fontMetrics);
        }

        if (image == null && textImage == null) {
            throw new IllegalArgumentException("Image or text must be defined for visual content!");
        }

        BufferedImage bufferedImage = DefaultImageDrawerUtils.mergeImages(image, textImage,
                dimensionAndPosition, parameters);
        bufferedImage = DefaultImageDrawerUtils.rotate(bufferedImage, dimensionAndPosition.getGlobalRotation());
        return bufferedImage;
    }

    /**
     * Copied from EU DSS lib.
     *
     * Builds a signature field dimension and position object
     *
     * @return {@link SignatureFieldDimensionAndPosition}
     */
    private static SignatureFieldDimensionAndPosition buildSignatureFieldBox(SignatureImageParameters parameters, PDDocument document) {
        PDPage originalPage = getPage(parameters, document);
        AnnotationBox pageBox = getPageAnnotationBox(originalPage);
        return new SignatureFieldDimensionAndPositionBuilder(parameters, getDSSFontMetrics(parameters), pageBox, originalPage.getRotation()).build();
    }

    private static PDPage getPage(SignatureImageParameters parameters, PDDocument document) {
        return document.getPage(parameters.getFieldParameters().getPage() - ImageUtils.DEFAULT_FIRST_PAGE);
    }

    /**
     * Copied from EU DSS lib.
     *
     * Gets a page annotation box
     *
     * @param pdPage {@link PDPage}
     * @return {@link AnnotationBox}
     */
    private static AnnotationBox getPageAnnotationBox(PDPage pdPage) {
        PDRectangle mediaBox = pdPage.getMediaBox();
        return new AnnotationBox(mediaBox.getLowerLeftX(), mediaBox.getLowerLeftY(),
                mediaBox.getUpperRightX(), mediaBox.getUpperRightY());
    }

    /**
     * Copied from EU DSS lib.
     */
    private static JavaDSSFontMetrics getDSSFontMetrics(SignatureImageParameters parameters) {
        SignatureImageTextParameters textParameters = parameters.getTextParameters();
        DSSFont dssFont = textParameters.getFont();

        Font javaFont = dssFont.getJavaFont();
        float properSize = dssFont.getSize() * ImageUtils.getScaleFactor(parameters.getZoom()); // scale text block
        Font properFont = javaFont.deriveFont(properSize);

        return new JavaDSSFontMetrics(properFont);
    }
}
