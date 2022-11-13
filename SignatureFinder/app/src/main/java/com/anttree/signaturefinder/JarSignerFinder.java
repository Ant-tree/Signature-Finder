package com.anttree.signaturefinder;

import android.util.Log;

import androidx.annotation.Nullable;

import com.anttree.signaturefinder.common.Utils;
import com.anttree.signaturefinder.model.MetaZipEntry;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

class JarSignerFinder {
    private static final String TAG = "JarSignerFinder";

    /**
     * InputStream reader buffer size
     */
    static final int BUFFER_SIZE = 4096;

    /**
     * Jar Signer Specs
     */
    static final String META_INF_DIR = "META-INF/";
    static final String MANIFEST_MF_EXACT_LOC = "META-INF/MANIFEST.MF";
    static final String SF_EXTENSION = ".SF";
    static final String RSA_EXTENSION = ".RSA";
    static final String DSA_EXTENSION = ".DSA";
    static final String EC_EXTENSION = ".EC";

    static final String MF_NAME_FIELD_PREFIX = "Name: ";

    private static final int SUPPORTED_HASH_SORT = 4;
    static final String[] DIGEST_MANIFEST = new String[]{
            "SHA1-Digest-Manifest-Main-Attributes: "        //Main-Attributes digest sort
            , "SHA-256-Digest-Manifest-Main-Attributes: "
            , "SHA-384-Digest-Manifest-Main-Attributes: "
            , "SHA-512-Digest-Manifest-Main-Attributes: "
            , "SHA1-Digest-Manifest: "                      //Entire digest sort
            , "SHA-256-Digest-Manifest: "
            , "SHA-384-Digest-Manifest: "
            , "SHA-512-Digest-Manifest: "
    };

    @Nullable
    byte[] findFirstCertificate(String filePath) {
        ArrayList<MetaZipEntry> signerEntries = new ArrayList<>();
        ArrayList<MetaZipEntry> sfEntries = new ArrayList<>();

        //Find MF Entry, and collect all SF entries with corresponding signer entries.
        MetaZipEntry manifestMfEntry = obtainMetaEntries(filePath
                , signerEntries
                , sfEntries);

        //If MANIFEST.MF file not found, or non of signer or sf exists, consider failed
        if (manifestMfEntry == null
                || signerEntries.size() < 1
                || sfEntries.size() < 1) {
            return null;
        }

        return getValidCertContent(manifestMfEntry
                , signerEntries
                , sfEntries);
    }

    /**
     * Obtain Meta entries
     * Following zip entries located in META-INF/ directories are the targets
     * - MANIFEST.MF file
     * - [ANY_VALID_NAME].SF file
     * - [ANY_VALID_NAME].RSA|DSA|EC
     * each of .SF file MUST be mapped with RSA|DSA|EC certificate with same name
     */
    @Nullable
    private MetaZipEntry obtainMetaEntries(String filePath
            , ArrayList<MetaZipEntry> signerEntries /*OUT*/
            , ArrayList<MetaZipEntry> sfEntries     /*OUT*/) {
        MetaZipEntry manifestMfEntry = null;

        ZipFile zipFile;
        try {
            zipFile = new ZipFile(filePath);
        } catch (IOException e) {
            return null;
        }

        for (ZipEntry zipEntry : Collections.list(zipFile.entries())) {
            String zipEntryName = zipEntry.getName();

            //Skip if entry is not in META-INF dir
            if (!zipEntryName.startsWith(META_INF_DIR)
                    && !(zipEntryName.endsWith(MANIFEST_MF_EXACT_LOC)
                    || zipEntryName.endsWith(SF_EXTENSION)
                    || zipEntryName.endsWith(RSA_EXTENSION)
                    || zipEntryName.endsWith(DSA_EXTENSION)
                    || zipEntryName.endsWith(EC_EXTENSION))) {
                continue;
            }

            try (InputStream inputStream = zipFile.getInputStream(zipEntry)) {
                if (zipEntryName.equals(MANIFEST_MF_EXACT_LOC)) {
                    byte[] entryBytes = uncompressOpenCurrentEntry(inputStream);
                    manifestMfEntry = new MetaZipEntry(zipEntryName, entryBytes);

                } else if (zipEntryName.endsWith(SF_EXTENSION)) {
                    byte[] entryBytes = uncompressOpenCurrentEntry(inputStream);
                    sfEntries.add(new MetaZipEntry(zipEntryName, entryBytes));

                } else if (zipEntryName.endsWith(RSA_EXTENSION)
                        || zipEntryName.endsWith(DSA_EXTENSION)
                        || zipEntryName.endsWith(EC_EXTENSION)) {
                    byte[] entryBytes = uncompressOpenCurrentEntry(inputStream);
                    signerEntries.add(new MetaZipEntry(zipEntryName, entryBytes));
                }
            } catch (IOException ignore) {
            }
        }
        return manifestMfEntry;
    }

    /**
     * Get valid certification and its content
     * VALID here means that this certificate has an SF file in same name
     * (pair such as CERT.SF and CERT.RSA),
     * and that SF file properly represents the hash of manifest file.
     */
    @Nullable
    private byte[] getValidCertContent(MetaZipEntry manifestMfEntry
            , ArrayList<MetaZipEntry> signerEntries
            , ArrayList<MetaZipEntry> sfEntries) {
        String validSfName = null;

        //Sort the collection in dictionary order of name
        //As MetaZipEntry is implementing Comparable, it is available to
        //sort using collection
        Collections.sort(sfEntries);

        //Check for entire entry, looks for the first valid SF file.
        for (MetaZipEntry entry : sfEntries) {
            if (isValidSFEntry(entry, manifestMfEntry)) {
                //When SF file is valid, it should have any cert file in same name
                validSfName = entry.getName().split(SF_EXTENSION)[0];
                break;
            }
        }

        if (validSfName == null) {
            return null;
        }

        for (MetaZipEntry entry : signerEntries) {
            if (entry.getName().contains(validSfName)) {
                return entry.getContent();
            }
        }

        return null;
    }

    /**
     * Valid SF entry specifies digest type and digest field
     * those specifications are located between the second - fifth line of itself
     * For instance,
     * <p>
     * When using SHA1 or SHA-256 as digest algorithm,
     * ---
     * Signature-Version: 1.0
     * Created-By: 1.0 (Android)
     * SHA-256-Digest-Manifest: u2QqKJam4zsgK4WBEDEoBS7doALo4rS40HpNteCIttk=
     * X-Android-APK-Signed: 2
     * ---
     * <p>
     * However when using SHA-384 or SHA-512 as an digest algorithm,
     * ---
     * Signature-Version: 1.0
     * SHA-512-Digest-Manifest-Main-Attributes: WxNuKk0PdD3/+WfZNxYXrLuQGm19x
     * P4J6JXIpNE1UXJHyHEAtD1T5boPmyB4TCEb8NEsio4+sErJmLybH0fH9Q==
     * SHA-512-Digest-Manifest: P/T4jIkS24/71qxQ6YmLxKMvDOQAtZ51GOttTsQOrzhGE
     * JZPeiYKrS6XcOtm+XiiET/nKkXuemQPpgdAG1JS1g==
     * Created-By: 1.8.0_45-internal (Oracle Corporation)
     * ---
     * <p>
     * the value of digest is represented in two-lines, with single white space on second line.
     * <p>
     * when those "specification" field ends with "Manifest-Main-Attributes",
     * it means it is an hashed value of the entire MANIFEST.MF file.
     * digest the entire MANIFEST.MF file otherwise.
     */
    private boolean isValidSFEntry(MetaZipEntry sfEntry, MetaZipEntry manifestMfEntry) {
        String content = new String(sfEntry.getContent());
        String[] lines = content.split("\n");

        for (int lineIndex = 1; lineIndex < 5; lineIndex++) {
            String line = lines[lineIndex];

            int digestSeq = searchDigestSequenceFromLine(line);
            if (digestSeq < 0) {
                continue;
            }

            // If digest seq's range is between
            // 0-3 : Main Attribute,
            // 4-7 : entire hash
            boolean isEntireHash = (digestSeq / SUPPORTED_HASH_SORT) > 0;
            // 0,4 : SHA-1
            // 1,5 : SHA-256
            // 2,6 : SHA-384
            // 3,7 : SHA-512
            int digestSort = digestSeq % SUPPORTED_HASH_SORT;
            String[] digestKeyValue = line.split(DIGEST_MANIFEST[digestSeq]);
            if (digestKeyValue.length != 2) {
                continue;
            }

            //Digest value when using SHA1 or SHA-256 is in single line form
            //However when it takes SHA-384 or SHA-512 as an value,
            //it will be represented in two-lines.
            String digestValue = digestSort < 2
                    ? digestKeyValue[1].trim()
                    : digestKeyValue[1].trim() + lines[lineIndex + 1].trim();

            byte[] hashTarget = isEntireHash
                    ? manifestMfEntry.getContent()
                    : getManifestMainAttrBytes(manifestMfEntry.getContent());

            String base64Digested = Utils.digestInBase64(digestSort, hashTarget);
            //Failed to get digest in base64 form
            if (base64Digested == null) {
                continue;
            }
            //when calculated digest
            if (!base64Digested.equals(digestValue)) {
                continue;
            }

            return true;
        }

        Log.d(TAG, "Valid SF Entry not found");
        return false;
    }

    private int searchDigestSequenceFromLine(String line) {
        if (line == null || line.length() < 1 || !line.startsWith("SHA")) {
            return ResultCode.FAILURE;
        }

        for (int index = 0; index < DIGEST_MANIFEST.length; index++) {
            if (line.startsWith(DIGEST_MANIFEST[index])) {
                return index;
            }
        }
        return ResultCode.FAILURE;
    }

    /**
     * When digest field of .SF file ends with Manifest-Main-Attributes,
     * it means that value of that field is calculated using main attributes only.
     * the main attribute starts from the file, and ends before first name field starts.
     * <p>
     * ---
     * Manifest-Version: 1.0
     * Created-By: 1.8.0_45-internal (Oracle Corporation)<<< UNTIL HERE IS THE MAIN ATTRIBUTE
     * <p>
     * Name: AndroidManifest.xml
     * SHA-512-Digest: /ja2RzXdhutgYf6XMKY99i+KI879k8SHKMPKDV2xYmxxaftVeOdiPk
     * ...
     * As of example, the main attributes are the section right before first Name field came out.
     */
    @Nullable
    private byte[] getManifestMainAttrBytes(byte[] entryBytes) {
        if (entryBytes == null) {
            return null;
        }
        int offset = 0;
        for (String line : new String(entryBytes).split("\n")) {
            //break the loop and skip line break when the first name field came out.
            //such is the last offset of main attributes.
            if (line.startsWith(MF_NAME_FIELD_PREFIX)) {
                break;
            }
            offset += line.length() + 1;
        }
        byte[] mainAttributeBytes = new byte[offset];
        System.arraycopy(entryBytes, 0, mainAttributeBytes, 0, offset);
        return mainAttributeBytes;
    }

    @Nullable
    private byte[] uncompressOpenCurrentEntry(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            return null;
        }

        //Closing a ByteArrayOutputStream has no effect
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[BUFFER_SIZE];
        int length;

        //Reading of zip input stream does not guarantees to be fully filled
        while ((length = inputStream.read(buffer)) != -1) {
            //When read bytes of input stream doesn't matches
            //buffer was not fully filled, and will have trailing zeros
            //Thus, removing those trailing zeros are necessary.
            if (length != BUFFER_SIZE) {
                byte[] validBytes = new byte[length];
                System.arraycopy(buffer, 0, validBytes, 0, length);
                outputStream.write(validBytes);
            }
            //buffer was fully filled, write as-is.
            else {
                outputStream.write(buffer);
            }
        }

        //Convert the output stream into bytearray and return
        return outputStream.toByteArray();
    }

}
