package se.signatureservice.support.utils;

import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.SimpleMessageSecurityProvider;

import java.util.Properties;
import java.util.UUID;

/**
 * Utility methods that can be used when working with the
 * support service library.
 *
 * @author Tobias Agerberg
 */
public class SupportLibraryUtils {

    /**
     * Create a simple message security provider.
     *
     * @param keyStorePath Path to key store to use when signing requests.
     * @param keyStorePassword Password that protects the key store.
     * @param keyStoreAlias Alias to private key within key store to use.
     * @param trustStorePath Path to trust store to use when verifying responses.
     * @param trustStorePassword Password that protects the trust store.
     * @return SimpleMessageSecurityProvider based on given parameters.
     * @throws MessageProcessingException If an error occurred when creating the message provider.
     */
    public static MessageSecurityProvider createSimpleMessageSecurityProvider(String keyStorePath, String keyStorePassword, String keyStoreAlias, String trustStorePath, String trustStorePassword) throws MessageProcessingException {
        Properties properties = new Properties();
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_PATH, keyStorePath);
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_PASSWORD, keyStorePassword);
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_ALIAS, keyStoreAlias);
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_TRUSTKEYSTORE_PATH, trustStorePath);
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_TRUSTKEYSTORE_PASSWORD, trustStorePassword);
        properties.setProperty(SimpleMessageSecurityProvider.SETTING_ENCRYPTION_ALGORITHM_SCHEME, "RSA_PKCS1_5_WITH_AES256");
        return new SimpleMessageSecurityProvider(properties);
    }

    /**
     * Generate a unique transaction ID that can be used to identify a particular
     * signature workflow.
     * @return a unique transaction ID
     */
    public static String generateTransactionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a unique reference ID that can be used to identify a particular
     * document during a transaction. This will also be used as ID for the
     * corresponding signtask.
     * @return a unique sign task ID
     */
    public static String generateReferenceId() {
        return UUID.randomUUID().toString();
    }
}
