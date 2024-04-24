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
package se.signatureservice.support.trustlist;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
import eu.europa.esig.dss.tsl.alerts.TLAlert;
import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLExpirationDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogLOTLLocationChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogOJUrlChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLExpirationAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Builder for when using List of Trusted Lists.
 *
 * @author Filip Wessman 2022-12-01
 */
public class TrustedListsCertificateSourceBuilder extends CommonCertificateSource {
    private static final Logger log = LoggerFactory.getLogger(TrustedListsCertificateSourceBuilder.class);

    private final String lotlURL;
    private final String ojURL;
    private final Boolean useOfflineLoader;
    private final Boolean acceptExpiredTrustedList;
    private final Boolean acceptInvalidTrustedList;
    private final String cacheDirectoryPath;
    private final long expirationTimeOnlineLoader;
    private final long expirationTimeOfflineLoader;
    private final String certificateSourceKeyStore;
    private final String certificateSourceKeyStoreType;
    private final String certificateSourceKeyStorePassword;

    private final TrustedListsCertificateSource trustedListsCertificateSource;
    private final TLValidationJob job;

    private final KeyStoreCertificateSource keyStoreCertificateSource;

    /**
     * Implementation constructor of the TrustedListsCertificateSourceBuilder.
     * Creates an instance of the TrustedListsCertificateSourceBuilder and sets up
     * the TL/LOTL download / parsing / validation tasks.
     *
     * @param lotlURL                           URL to the LOTL to be parsed.
     * @param ojURL                             URL to the Official Journal Scheme.
     * @param useOfflineLoader                  Specify how all data will be updated and parsed, online or offline.
     * @param acceptExpiredTrustedList          If expired list of trusted lists and their TLs are supported.
     * @param acceptInvalidTrustedList          If invalid list of trusted lists and their TLs are supported.
     * @param cacheDirectoryPath                Custom directory path to were LOTL and TL validation files will be cached.
     * @param expirationTimeOnlineLoader        Expiration time for the cached validation files in *minutes*, used when 'useOfflineLoader' is set to false.
     * @param expirationTimeOfflineLoader       Expiration time for the cached validation files in *minutes*, used when 'useOfflineLoader' is set to true.
     * @param certificateSourceKeyStore         Path to Keystore containing certificate used for custom LOTL/TL signature validation.
     * @param certificateSourceKeyStoreType     Type of the Keystore certificate source.
     * @param certificateSourceKeyStorePassword Password of the Keystore certificate source.
     * @param keyStoreCertificateSource         KeyStoreCertificateSource used as a Trusted Certificate Source.
     */
    public TrustedListsCertificateSourceBuilder(final String lotlURL, final String ojURL, final Boolean useOfflineLoader, final Boolean acceptExpiredTrustedList, final Boolean acceptInvalidTrustedList,
                                                final String cacheDirectoryPath, final long expirationTimeOnlineLoader, final long expirationTimeOfflineLoader, final String certificateSourceKeyStore,
                                                final String certificateSourceKeyStoreType, final String certificateSourceKeyStorePassword, final KeyStoreCertificateSource keyStoreCertificateSource) {
        this.lotlURL = lotlURL;
        this.ojURL = ojURL;
        this.useOfflineLoader = useOfflineLoader;
        this.acceptExpiredTrustedList = acceptExpiredTrustedList;
        this.acceptInvalidTrustedList = acceptInvalidTrustedList;
        this.cacheDirectoryPath = cacheDirectoryPath;
        this.expirationTimeOnlineLoader = expirationTimeOnlineLoader;
        this.expirationTimeOfflineLoader = expirationTimeOfflineLoader;
        this.certificateSourceKeyStore = certificateSourceKeyStore;
        this.certificateSourceKeyStoreType = certificateSourceKeyStoreType;
        this.certificateSourceKeyStorePassword = certificateSourceKeyStorePassword;
        this.keyStoreCertificateSource = keyStoreCertificateSource;

        this.job = validationJob();
        this.trustedListsCertificateSource = new TrustedListsCertificateSource();
        job.setTrustedListCertificateSource(trustedListsCertificateSource);
        log.info("Using " + (useOfflineLoader ? "OfflineLoader." : "OnlineLoader."));
        if (this.useOfflineLoader) {
            job.offlineRefresh();
        } else {
            job.onlineRefresh();
        }
    }

    /**
     * Implementation constructor of the TrustedListsCertificateSourceBuilder.
     * Creates an instance of the TrustedListsCertificateSourceBuilder and sets up
     * the TL/LOTL download / parsing / validation tasks.
     *
     * @param lotlURL                     URL to the LOTL to be parsed.
     * @param ojURL                       URL to the Official Journal Scheme.
     * @param useOfflineLoader            Specify how all data will be updated and parsed, online or offline.
     * @param cacheDirectoryPath          Custom directory path to were LOTL and TL validation files will be cached.
     * @param expirationTimeOnlineLoader  Expiration time for the cached validation files in *minutes*, used when 'useOfflineLoader' is set to false.
     * @param expirationTimeOfflineLoader Expiration time for the cached validation files in *minutes*, used when 'useOfflineLoader' is set to true.
     */
    public TrustedListsCertificateSourceBuilder(final String lotlURL, final String ojURL, final boolean useOfflineLoader, final String cacheDirectoryPath, final long expirationTimeOnlineLoader, final long expirationTimeOfflineLoader) {
        this(lotlURL, ojURL, useOfflineLoader, false, false, cacheDirectoryPath, expirationTimeOnlineLoader,
                expirationTimeOfflineLoader, null, null, null, null);
    }

    /**
     * Method to get the instance of this class TrustedListsCertificateSource.
     *
     * @return TrustedListsCertificateSource.
     */
    public TrustedListsCertificateSource getTrustedListsCertificateSource() {
        return this.trustedListsCertificateSource;
    }

    /**
     * Method to get the instance of this class KeyStoreCertificateSource.
     *
     * @return KeyStoreCertificateSource.
     */
    public KeyStoreCertificateSource getKeyStoreCertificateSource() {
        return this.keyStoreCertificateSource;
    }

    /**
     * Get a new TrustedListsCertificateSource.
     *
     * @return TrustedListsCertificateSource.
     */
    private TrustedListsCertificateSource trustedCertificateSource() {
        return new TrustedListsCertificateSource();
    }

    /**
     * Method to get the instance of this class TLValidationJob.
     *
     * @return TLValidationJob.
     */
    public TLValidationJob getTLValidationJob() {
        return this.job;
    }

    /**
     * Method for performing the LOTL/TL download / parsing / validation tasks.
     *
     * @return TLValidationJob.
     */
    private TLValidationJob validationJob() {
        TLValidationJob validationJob = new TLValidationJob();
        validationJob.setOfflineDataLoader(offlineLoader());
        validationJob.setOnlineDataLoader(onlineLoader());
        validationJob.setTrustedListCertificateSource(trustedCertificateSource());

        ExpirationAndSignatureCheckStrategy checkStrategy = new ExpirationAndSignatureCheckStrategy();
        checkStrategy.setAcceptExpiredListOfTrustedLists(acceptExpiredTrustedList);
        checkStrategy.setAcceptExpiredTrustedList(acceptExpiredTrustedList);
        checkStrategy.setAcceptInvalidListOfTrustedLists(acceptInvalidTrustedList);
        checkStrategy.setAcceptInvalidTrustedList(acceptInvalidTrustedList);
        validationJob.setSynchronizationStrategy(checkStrategy);

        validationJob.setCacheCleaner(cacheCleaner());
        LOTLSource europeanLOTL = europeanLOTL();
        validationJob.setListOfTrustedListSources(europeanLOTL);

        //After the download/parsing/validation and before the synchronization, the results are tested to detect events and launch alert(s).
        validationJob.setLOTLAlerts(Arrays.asList(ojUrlAlert(europeanLOTL), lotlLocationAlert(europeanLOTL)));
        validationJob.setTLAlerts(Arrays.asList(tlSigningAlert(), tlExpirationDetection()));

        return validationJob;
    }

    /**
     * List of Trusted Lists source with specified TL access URL and CertificateSource.
     *
     * @return List of Trusted Lists source
     */
    private LOTLSource europeanLOTL() {
        LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl(Objects.requireNonNull(lotlURL));

        if (certificateSourceKeyStore != null && certificateSourceKeyStoreType != null && certificateSourceKeyStorePassword != null) {
            lotlSource.setCertificateSource(certificateSourceKeyStore());
        } else {
            log.info("Using Default Official Journal Keystore for TL validation.");
            lotlSource.setCertificateSource(officialJournalContentKeyStore());
        }

        if (ojURL != null) {
            log.info("Setting CertificatesAnnouncementPredicate with: " + ojURL);
            lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(ojURL));
        }
        lotlSource.setPivotSupport(true);

        return lotlSource;
    }

    /**
     * EU DSS Official Journal Keystore CertificateSource which contains certificate used for LOTL/TL signature validation.
     *
     * @return KeyStoreCertificateSource used for LOTL/TL validation.
     */
    public CertificateSource officialJournalContentKeyStore() {
        try {
            return new KeyStoreCertificateSource(TrustedListsCertificateSourceBuilder.class.getResourceAsStream("lotl/oj-keystore.p12"), "PKCS12", "dss-password".toCharArray());
        } catch (NullPointerException e) {
            throw new DSSException("Unable to load the keystore", e);
        }
    }

    /**
     * Sets a Keystore CertificateSource which contains certificate used for custom LOTL/TL signature validation.
     *
     * @return KeyStoreCertificateSource used for LOTL/TL validation.
     */
    private CertificateSource certificateSourceKeyStore() {
        try {
            log.info("Using KeyStoreCertificateSource for LOTL/TL validation. Keystore: " + certificateSourceKeyStore +
                    ", KeyStoreType: " + certificateSourceKeyStoreType + ", KeyStorePassword: " + certificateSourceKeyStorePassword);
            return new KeyStoreCertificateSource(certificateSourceKeyStore, certificateSourceKeyStoreType, certificateSourceKeyStorePassword.toCharArray());
        } catch (IOException e) {
            throw new DSSException("Unable to load the keystore", e);
        }
    }

    /**
     * Creates a file cache DataLoader with which can't access and download from the Internet.
     * With a Cache Expiration Time and path to cache directory.
     *
     * @return DSSFileLoader which can access to Internet.
     */
    private DSSFileLoader offlineLoader() {
        FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(expirationTimeOfflineLoader < 0 ? -1 : expirationTimeOfflineLoader * 60000);
        offlineFileLoader.setDataLoader(new IgnoreDataLoader()); // do not download from Internet
        offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
        return offlineFileLoader;
    }

    /**
     * Creates a file cache DataLoader with which can access to Internet.
     * With a Cache Expiration Time and path to cache directory.
     *
     * @return DSSFileLoader which can access to Internet.
     */
    private DSSFileLoader onlineLoader() {
        FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(expirationTimeOnlineLoader < 0 ? -1 : expirationTimeOnlineLoader * 60000);
        onlineFileLoader.setDataLoader(new CommonsDataLoader()); // instance of DataLoader which can access to Internet (proxy,...)
        onlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
        return onlineFileLoader;
    }

    /**
     * Creates a Trusted List cache directory.
     * Either default java.io.tmpdir or if defined, a user specified directory path.
     *
     * @return File instance of the Trusted List cache directory.
     */
    private File tlCacheDirectory() {
        File tslCache;
        if (cacheDirectoryPath != null) {
            tslCache = new File(cacheDirectoryPath);
        } else {
            File rootFolder = new File(System.getProperty("java.io.tmpdir"));
            tslCache = new File(rootFolder, "dss-tsl-loader");
        }
        if (tslCache.mkdirs()) {
            log.info("TL Cache folder : {}", tslCache.getAbsolutePath());
        }
        return tslCache;
    }

    /**
     * Specifies how DSS clears the cache.
     * Free space in memory and remove the stored file(s) on the file-system.
     *
     * @return CacheCleaner with its corresponding settings.
     */
    private CacheCleaner cacheCleaner() {
        CacheCleaner cacheCleaner = new CacheCleaner();
        cacheCleaner.setCleanMemory(true);
        cacheCleaner.setCleanFileSystem(true);

        // if the file-system cleaner is enabled, inject the configured loader from the online or offline refresh data loader.
        cacheCleaner.setDSSFileLoader(useOfflineLoader ? offlineLoader() : onlineLoader());
        return cacheCleaner;
    }

    /**
     * Detects and Warns if am TrustedList validation occurred.
     *
     * @return TLAlert.
     */
    private TLAlert tlSigningAlert() {
        TLSignatureErrorDetection signingDetection = new TLSignatureErrorDetection();
        LogTLSignatureErrorAlertHandler handler = new LogTLSignatureErrorAlertHandler();
        return new TLAlert(signingDetection, handler);
    }

    /**
     * Detects and Warns if a TrustedList expires.
     *
     * @return TLAlert.
     */
    private TLAlert tlExpirationDetection() {
        TLExpirationDetection expirationDetection = new TLExpirationDetection();
        LogTLExpirationAlertHandler handler = new LogTLExpirationAlertHandler();
        return new TLAlert(expirationDetection, handler);
    }

    /**
     * Detects and Warns if the LOTL Official Journal URL changes.
     *
     * @param source List of Trusted Lists source.
     * @return LOTLAlert.
     */
    private LOTLAlert ojUrlAlert(LOTLSource source) {
        OJUrlChangeDetection ojUrlDetection = new OJUrlChangeDetection(source);
        LogOJUrlChangeAlertHandler handler = new LogOJUrlChangeAlertHandler();
        return new LOTLAlert(ojUrlDetection, handler);
    }

    /**
     * Detects and Warns if the LOTL location changes.
     *
     * @param source List of Trusted Lists source.
     * @return LOTLAlert.
     */
    private LOTLAlert lotlLocationAlert(LOTLSource source) {
        LOTLLocationChangeDetection lotlLocationDetection = new LOTLLocationChangeDetection(source);
        LogLOTLLocationChangeAlertHandler handler = new LogLOTLLocationChangeAlertHandler();
        return new LOTLAlert(lotlLocationDetection, handler);
    }
}
