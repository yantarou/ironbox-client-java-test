package ironbox;

import com.goironbox.client.ApiVersion;
import com.goironbox.client.BlobInfo;
import com.goironbox.client.BlobState;
import com.goironbox.client.ContainerInfo;
import com.goironbox.client.ContainerKeyData;
import com.goironbox.client.ContainerType;
import com.goironbox.client.ContentFormat;
import com.goironbox.client.ContextSetting;
import com.goironbox.client.EntityType;
import com.goironbox.client.IronBoxClient;
import com.goironbox.client.SFTContainerConfig;
import java.io.File;
import java.io.FileInputStream;
import java.util.List;
import org.apache.commons.codec.digest.DigestUtils;

public class App 
{
    private static final String CONTEXT = "secure.goironcloud.com";
    private static final String USER = "apidemo@goironcloud.com";
    private static final String PASS = "password123**";

    private static final String TEST_CONTAINER_NAME = "ironbox-client-java test container";
    private static final String TEST_CONTAINER_DESCRIPTION = "description for " + TEST_CONTAINER_NAME;

    private static final String TESTFILE_DIR = "src/test/resources";

    public static void main(String[] args)
    {
        try {
            App app = new App();
            app.run();
        }
        catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }

    private void run() throws Exception {
        // Create instance of IronBox REST client.
        // IronBoxClient ibc = new IronBoxClient(USER, PASS);
        IronBoxClient ibc = new IronBoxClient(
            USER, PASS, EntityType.EMAIL_ADDRESS,
            ApiVersion.LATEST, ContentFormat.JSON,
            true, true
        );

        // Get context's company name.
        log("Company name: %s", ibc.getContextSetting(CONTEXT, ContextSetting.COMPANY_NAME));

        // Get context's company logo URL.
        log("Company logo URL: %s", ibc.getContextSetting(CONTEXT, ContextSetting.COMPANY_LOGO_URL));
        
        // Delete existing container(s).
        List<Long> containerIDs = ibc.getContainerIDsFromName(TEST_CONTAINER_NAME);
        log("Found %d existing container(s).", containerIDs.size());
        for (Long containerID : containerIDs) {
            log("Removing container with ID '%d'...", containerID);
            if (!ibc.removeEntityContainer(containerID)) {
                log("Removal failed!");
            }
        }

        // Create new container.
        SFTContainerConfig cc = ibc.createEntitySFTContainer(CONTEXT, TEST_CONTAINER_NAME, TEST_CONTAINER_DESCRIPTION);

        // Get container's encrytion key data.
        ContainerKeyData ckd = ibc.getContainerKeyData(cc.getContainerID());

        // Test local en/decryption.
        for (File localFile : new File(TESTFILE_DIR).listFiles()) {
            File encryptedFile = File.createTempFile("encrypted", ".tmp");
            encryptedFile.deleteOnExit();
            IronBoxClient.encryptFile(localFile, encryptedFile, ckd);

            File decryptedFile = File.createTempFile("decrypted", ".tmp");
            decryptedFile.deleteOnExit();
            IronBoxClient.decryptFile(encryptedFile, decryptedFile, ckd);

            String localFileMD5 = DigestUtils.md5Hex(new FileInputStream(localFile));
            log("Local MD5:      %s, [%s, %s, %d]", localFileMD5, localFile.getAbsolutePath(), localFile.exists(), localFile.length());
            String encryptedFileMD5 = DigestUtils.md5Hex(new FileInputStream(encryptedFile));
            log("Encrypted MD5:  %s, [%s, %s, %d]", encryptedFileMD5, encryptedFile.getAbsolutePath(), encryptedFile.exists(), encryptedFile.length());
            String decryptedFileMD5 = DigestUtils.md5Hex(new FileInputStream(decryptedFile));
            log("Decrypted MD5:  %s, [%s, %s, %d]", decryptedFileMD5, decryptedFile.getAbsolutePath(), decryptedFile.exists(), decryptedFile.length());
            if (!localFileMD5.equals(decryptedFileMD5)) {
                throw new Exception("MD5SUM mismatch!");
            }
        }
        
        for (File localFile : new File(TESTFILE_DIR).listFiles()) {
            String blobName = localFile.getName() + ".test";
            String blobID = "";
            
            // Upload local file to container.
            ibc.uploadFileToContainer(cc.getContainerID(), localFile, blobName);
            
            for (ContainerInfo ci : ibc.getContainerInfoListByContext(CONTEXT, ContainerType.DEFAULT)) {
                log("Container info: %s (%s)", ci.getContainerID(), ci.getContainerName());
            }
            
            for (BlobState bs : BlobState.values()) {
                log("Blob state: %s", bs.name());
                for (BlobInfo bi : ibc.getContainerBlobInfoListByState(cc.getContainerID(), bs)) {
                    log("Blob info: %s (%s)", bi.getBlobID(), bi.getBlobName());
                    if (blobName.equals(bi.getBlobName())) {
                        blobID = bi.getBlobID();
                        log("BLOB ID: " + blobID);
                    }
                }
            }
            
            // Download blob.
            File downloadedFile = File.createTempFile("downloaded", ".tmp");
            ibc.downloadBlobFromContainer(cc.getContainerID(), blobID, downloadedFile);
            
            // Verify checksums.
            String localFileMD5 = DigestUtils.md5Hex(new FileInputStream(localFile));
            log("Local MD5:      %s, [%s, %s, %d]", localFileMD5, localFile.getAbsolutePath(), localFile.exists(), localFile.length());
            String downloadedFileMD5 = DigestUtils.md5Hex(new FileInputStream(downloadedFile));
            log("Downloaded MD5: %s, [%s, %s, %d]", downloadedFileMD5, downloadedFile.getAbsolutePath(), downloadedFile.exists(), downloadedFile.length());

            if (!localFileMD5.equals(downloadedFileMD5)) {
                throw new Exception("MD5SUM mismatch!");
            }
        }
    }
    
    private void log(String format, Object ... args) {
        System.out.println(String.format(format, args));
    }

}
