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

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfSignatureFieldPositionChecker;
import eu.europa.esig.dss.pdf.modifications.PdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandlerBuilder;

/**
 * Custom object factory to control configuration of PDF signature service.
 *
 * @author Tobias Agerberg
 */
public class PdfBoxSupportObjectFactory extends PdfBoxDefaultObjectFactory {
    private DSSResourcesHandlerBuilder resourcesHandlerBuilder;

    /**
     * Used to find differences occurred between PDF revisions (e.g. visible changes).
     */
    private PdfDifferencesFinder pdfDifferencesFinder;

    /**
     * Used to find differences within internal PDF objects occurred between PDF revisions .
     */
    private PdfObjectModificationsFinder pdfObjectModificationsFinder;

    public PdfBoxSupportObjectFactory(){
        super();
    }

    @Override
    public void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
        this.resourcesHandlerBuilder = resourcesHandlerBuilder;
    }

    @Override
    public void setPdfDifferencesFinder(PdfDifferencesFinder pdfDifferencesFinder) {
        this.pdfDifferencesFinder = pdfDifferencesFinder;
    }

    @Override
    public void setPdfObjectModificationsFinder(PdfObjectModificationsFinder pdfObjectModificationsFinder) {
        this.pdfObjectModificationsFinder = pdfObjectModificationsFinder;
    }

    @Override
    protected PDFSignatureService configure(PDFSignatureService pdfSignatureService) {
        if (resourcesHandlerBuilder != null) {
            pdfSignatureService.setResourcesHandlerBuilder(resourcesHandlerBuilder);
        }
        if (pdfDifferencesFinder != null) {
            pdfSignatureService.setPdfDifferencesFinder(pdfDifferencesFinder);
        }
        if (pdfObjectModificationsFinder != null) {
            pdfSignatureService.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);
        }

        // Disable errors for visible signatures covering text within PDF. It is not a good user experience
        // if application crashes because signature image covers text slightly. We trust the user this case.
        if(pdfSignatureService instanceof AbstractPDFSignatureService){
            PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker = new PdfSignatureFieldPositionChecker();
            pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOverlap(new SilentOnStatusAlert());
            pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new SilentOnStatusAlert());
            pdfSignatureService.setPdfSignatureFieldPositionChecker(pdfSignatureFieldPositionChecker);
        }

        return pdfSignatureService;
    }
}
