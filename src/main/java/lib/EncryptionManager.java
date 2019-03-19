package lib;

import enums.KeyAlgorithms;
import enums.KeyLengths;
import exception.EncryptionManagerException;
import org.apache.commons.io.FileUtils;
import org.jetbrains.annotations.Nullable;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * <h1>EncryptionManager</h1>
 * <p>Utility class used to manage encryption, can be used to decrypt encrypted configuration values</p>
 *
 * @author jackbranch
 */
public final class EncryptionManager {

    private static final Logger LOGGER = Logger.getLogger(EncryptionManager.class.getName());
    private static final String CYPHER_NAME = "AES/CBC/PKCS5Padding";
    private static final String KEY_FILE_PATH = "";
    private static final String AES = "AES";

    private int iterationCount = 40000;
    private int keyLength = KeyLengths.ONE_TWO_EIGHT.toInt();
    private byte[] salt = "87654321".getBytes();
    private String keyAlg = KeyAlgorithms.PBKDF.toString();

    private SecretKeySpec keySpec;

    /**
     * <h2>EncryptionManager</h2>
     * <p>Constructor for EncryptionManager, checks whether key file is present, if so sets key spec from file,
     * if not creates new key file / spec, throws {@link EncryptionManagerException} if File Io fails</p>
     *
     * @param filePath can be null, if null uses default file path, intended to be fore test cases when not null
     */
    public EncryptionManager(String pubKey, @Nullable String filePath) {
        File keyFile = new File(null == filePath ? KEY_FILE_PATH : filePath);
        if (!keyFile.isFile()) {
            keySpec = createSecretKey(pubKey.toCharArray(), filePath);
        } else {
            try {
                byte[] encoded = Files.readAllBytes(keyFile.toPath());
                keySpec = new SecretKeySpec(encoded, AES);
            } catch (IOException e) {
                LOGGER.warning(e.getMessage());
                throw new EncryptionManagerException("Encryption Failed: ", e);
            }
        }
    }

    public void setIterationCount(int count) {
        this.iterationCount = count;
    }

    public void setKeyLength(KeyLengths length) {
        this.keyLength = length.toInt();
    }

    public void setSalt(String val) {
        this.salt = val.getBytes();
    }

    public void setSalt(byte[] bytes) {
        this.salt = bytes;
    }

    public void setKeyAlg(KeyAlgorithms alg) {
        this.keyAlg = alg.toString();
    }

    /**
     * <h2>decryptDbPassword</h2>
     * <p>Decrypts a password string using set encryption algorithm, throws if input / password is invalid</p>
     *
     * @param encryptedString string to decrypt
     * @return decrypted password
     */
    public String decryptDbPassword(String encryptedString) {
        String iv = encryptedString.split(":")[0];
        String value = encryptedString.split(":")[1];
        try {
            Cipher cipher = Cipher.getInstance(CYPHER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(Base64.getDecoder().decode(iv)));
            return new String(cipher.doFinal(Base64.getDecoder().decode(value)));
        } catch (Exception e) {
            LOGGER.warning(e.getMessage());
            LOGGER.throwing(EncryptionManager.class.getName(), "decryptPassword", e);
            throw new EncryptionManagerException("Decryption failed: ", e);
        }
    }

    /**
     * <h2>encryptPassword</h2>
     * <p>Encrypts a given password using the parameters set by EncryptionManager, use to created encrypted string from
     * input</p>
     *
     * @param password input password / string to be encrypted
     * @return encrypted string of input value
     */
    public String encryptPassword(String password) {
        try {
            Cipher cipher = Cipher.getInstance(CYPHER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            AlgorithmParameters parameters = cipher.getParameters();
            IvParameterSpec parameterSpec = parameters.getParameterSpec(IvParameterSpec.class);
            byte[] cryptedText = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
            byte[] iv = parameterSpec.getIV();
            return base64Encode(iv).concat(":").concat(base64Encode(cryptedText));
        } catch (Exception e) {
            LOGGER.throwing(EncryptionManager.class.getName(), "encryptPassword", e);
            throw new EncryptionManagerException("Encryption failed: ", e);
        }
    }

    /**
     * <h2>createSecretKey</h2>
     * <p>Creates a secret key from the public key and EncryptionManager settings, returns this key  and saves key to
     * file, if filename is specified then saves to specific location otherwise saves to default location</p>
     *
     * @param pubKey   public key, by default loaded from configuration file
     * @param filename can be null if saving to default location, otherwise saves key file to specific path
     * @return SecretKeySpec created from public key
     */
    private SecretKeySpec createSecretKey(char[] pubKey, @Nullable String filename) {
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(keyAlg);
            PBEKeySpec spec = new PBEKeySpec(pubKey, salt, iterationCount, keyLength);
            SecretKey keyTmp = secretKeyFactory.generateSecret(spec);
            FileUtils.writeByteArrayToFile(new File(null == filename ? KEY_FILE_PATH : filename), keyTmp.getEncoded());
            return new SecretKeySpec(keyTmp.getEncoded(), AES);
        } catch (Exception e) {
            LOGGER.warning(e.getMessage());
            throw new EncryptionManagerException("Key generation failed: ", e);
        }
    }

    /**
     * <h2>base64Encode</h2>
     * <p>Base64 encodes a byte[] to a string, used to process encrypted bytes into string</p>
     *
     * @param value input byte[] to be encoded
     * @return encoded string version of byte[]
     */
    private String base64Encode(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }
}
