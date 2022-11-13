package com.anttree.signaturefinder;

import static com.anttree.signaturefinder.common.BytesLength.SIZE_INT64_BYTES;
import static com.anttree.signaturefinder.common.BytesLength.SIZE_INT_BYTES;

import android.util.Log;
import android.util.Pair;

import com.anttree.signaturefinder.common.Endianness;
import com.anttree.signaturefinder.common.Utils;
import com.anttree.signaturefinder.model.SignatureScheme;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;

/**
 * Finds first certificate from each signature block
 * <p>
 * <p>
 * +----------------------------------------------------+
 * | size of signers                         4 bytes    |
 * +----------------------------------------------------+
 * | size of signer                          4 bytes    |
 * +----------------------------------------------------+
 * | size of digests                         4 bytes    |
 * +-------------+--------------------------------------+
 * |             |                                      |
 * |   digests   |                      size of digests |
 * |             |                                      |
 * +-------------+--------------------------------------+
 * | size of certificates                    4 bytes    |
 * +-------------+-----------------------+--------------+
 * |             | size of enc. cert (4) | size of      |
 * |   certs     +-----------------------| certificates |
 * |             | enc. cert             |              |
 * +-------------+-----------------------+--------------+
 */
public class SignatureFinder {
    private static final String TAG = "SignatureFinder";

    /**
     * EOC Specs
     */
    static final int EOC_SEEK_MAX = 0x16 + 0xFFFF;
    static final int EOC_HEADER_SIZE = 22;
    static final byte[] EOC_HEADER_MAGIC = new byte[]{0x50, 0x4b, 0x05, 0x06};
    static final int EOC_HEADER_CENTRAL_DIR_SIZE_OFFSET = 12;
    static final int EOC_HEADER_CENTRAL_DIR_START_OFFSET = 16;

    /**
     * APK Signer Specs
     */
    static final String SIGNATURE_BLOCK_MAGIC = "APK Sig Block 42";
    static final int BLOCK_ID_SCHEME_VERSION2 = 0x7109871a;
    static final int BLOCK_ID_SCHEME_VERSION3 = 0xf05368c0;
    static final int BLOCK_ID_SCHEME_VERSION3_1 = 0x1b93ad61;

    static final int STRIPPING_PROTECTION_ATTR_ID = 0xbeeff00d;
    static final int PROOF_OF_ROTATION_ATTR_ID = 0x3ba06f8c;
    static final int VERITY_PADDING_BLOCK_ID = 0x42726577;

    public ArrayList<SignatureScheme> findCertSignature(String path) {
        int centralDirOffset = findCentralDirectory(path);
        if (centralDirOffset < 0) {
            return null;
        }

        byte[] sigBlock = findSigBlock(path, centralDirOffset);
        if (sigBlock == null) {
            return null;
        }

        //Retrieve the first certificate among from the UNBROKEN schemes.
        ArrayList<SignatureScheme> signatureSchemes = findCertPairs(sigBlock);

        byte[] jarSignerBytes = new JarSignerFinder().findFirstCertificate(path);
        byte[] jarSignerCertificate = null;
        try {
            Certificate certificate = CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(jarSignerBytes));

            jarSignerCertificate = certificate.getEncoded();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        signatureSchemes.add(new SignatureScheme(SignatureScheme.SCHEME_V1
                , jarSignerBytes
                , jarSignerCertificate));

        return signatureSchemes;
    }

    private int findCentralDirectory(String path) {
        File file = new File(path);
        final int EOC_FIND_SIZE;

        if (!file.exists() || file.length() < 1) {
            return ResultCode.RET_ERR_FILE_OPEN;
        }

        //If file length is longer than EOC SEEK MAX,
        //EOC_FIND_MAX will be EOC_SEEK_MAX.
        //Find from the first indexed byte of the file otherwise.
        if (file.length() > EOC_SEEK_MAX) {
            EOC_FIND_SIZE = EOC_SEEK_MAX;
        } else {
            EOC_FIND_SIZE = (int) file.length();
        }

        int seekStart = (int) (file.length() - EOC_FIND_SIZE);
        byte[] fileBytes = Utils.fileReader(file, seekStart, EOC_FIND_SIZE);
        if (fileBytes == null) {
            return ResultCode.RET_ERR_FILE_LENGTH;
        }

        int centralDirEOCOffset = -1;
        int sizeOfTheCentralDir = -1;
        int offSetOfCentralDir = -1;

        //Find EOC HEADER MAGIC from the last (backward)
        for (int position = EOC_FIND_SIZE - EOC_HEADER_SIZE; position > 0; position--) {
            if (position - EOC_HEADER_MAGIC.length < 0) {
                break;
            }

            if (fileBytes[position] == EOC_HEADER_MAGIC[0]
                    && fileBytes[position + 1] == EOC_HEADER_MAGIC[1]
                    && fileBytes[position + 2] == EOC_HEADER_MAGIC[2]
                    && fileBytes[position + 3] == EOC_HEADER_MAGIC[3]) {
                //centralDirOffset EOC found
                centralDirEOCOffset = seekStart + position;
                Log.d(TAG, "centralDirOffset EOC found!, index : " + position + ", seekStart : " + seekStart);

                sizeOfTheCentralDir = Endianness.leBytesToInt(fileBytes
                        , position + EOC_HEADER_CENTRAL_DIR_SIZE_OFFSET);

                offSetOfCentralDir = Endianness.leBytesToInt(fileBytes
                        , position + EOC_HEADER_CENTRAL_DIR_START_OFFSET);

                //Only one EOC exists, so break right away
                break;
            }
        }

        //Consider failed if any of those data is not found
        if (centralDirEOCOffset == -1 || sizeOfTheCentralDir == -1 || offSetOfCentralDir == -1) {
            return ResultCode.RET_INVALID_DATA;
        }

        //For verification & double check
        int offSetOfCentralDirCalculated = (centralDirEOCOffset - sizeOfTheCentralDir);

        //Calculated central dir offset doesn't matches the offset that defined in a block
        if (offSetOfCentralDir != offSetOfCentralDirCalculated) {
            return ResultCode.RET_INVALID_DATA;
        }

        return offSetOfCentralDirCalculated;
    }

    public byte[] findSigBlock(String path, int centralDirOffset) {
        File file = new File(path);

        byte[] fileBytes = Utils.fileReader(file
                , centralDirOffset - SIGNATURE_BLOCK_MAGIC.length()
                , SIGNATURE_BLOCK_MAGIC.length());

        String magicString = new String(fileBytes);

        if (fileBytes == null || !magicString.equalsIgnoreCase(SIGNATURE_BLOCK_MAGIC)) {
            //Section magic not matches
            Log.d(TAG, "Section magic not matches, magicString : " + magicString);
            return null;
        }

        fileBytes = Utils.fileReader(file
                , centralDirOffset - (SIZE_INT64_BYTES + SIGNATURE_BLOCK_MAGIC.length())
                , SIZE_INT64_BYTES);

        if (fileBytes == null) {
            //No file bytes with corresponding offset
            return null;
        }

        int blockSize = (int) Endianness.leBytesToLong(fileBytes, 0);
        int blockStartOffset = (centralDirOffset - blockSize);

        fileBytes = Utils.fileReader(file, blockStartOffset, blockSize);

        return fileBytes;
    }

    public ArrayList<SignatureScheme> findCertPairs(byte[] block) {
        ArrayList<SignatureScheme> signatureSchemes = new ArrayList<>();

        int signingBlockSize = block.length;
        int pointer = 0;

        do {
            Pair<Integer, SignatureScheme> pair = getNextScheme(pointer, block);
            if (pair == null) {
                //Unidentified scheme, exit!
                break;
            }
            if (pair.second == null) {
                pointer = pair.first;
                continue;
            }
            pointer = pair.first;
            signatureSchemes.add(pair.second);
        } while (pointer < signingBlockSize - 12);

        return signatureSchemes;
    }

    private Pair<Integer, SignatureScheme> getNextScheme(int pointer, byte[] block) {
        int schemeBlockSize = (int) Endianness.leBytesToLong(block, pointer);
        int schemeVersion;
        pointer += SIZE_INT64_BYTES;

        if (schemeBlockSize > block.length) {
            return null;
        }

        int signatureId = Endianness.leBytesToInt(block, pointer);

        if (signatureId == BLOCK_ID_SCHEME_VERSION2) {
            schemeVersion = 2;
        } else if (signatureId == BLOCK_ID_SCHEME_VERSION3) {
            schemeVersion = 3;
        } else if (signatureId == BLOCK_ID_SCHEME_VERSION3_1
                || signatureId == STRIPPING_PROTECTION_ATTR_ID
                || signatureId == PROOF_OF_ROTATION_ATTR_ID
                || signatureId == VERITY_PADDING_BLOCK_ID) {
            return new Pair<>(pointer, null);
        } else {
            return null;
        }

        Log.d(TAG, String.format("[SIGNATURE ID] : 0x%08x", signatureId));

        byte[] sigBlockData = new byte[schemeBlockSize];

        System.arraycopy(block, pointer + 4, sigBlockData, 0, schemeBlockSize);
        pointer += schemeBlockSize;

        //Even though scheme version varies and version 2 and 3 are slightly different,
        //both can be treated same since we only care the first certificate.
        byte[] firstCertificateData = getFirstCertificate(sigBlockData);

        return new Pair<>(pointer, new SignatureScheme(schemeVersion
                , sigBlockData
                , firstCertificateData));
    }

    private byte[] getFirstCertificate(byte[] signerBlock) {
        int pointer = 0;

        int signersSize = Endianness.leBytesToInt(signerBlock, pointer);
        if (signersSize > signerBlock.length || signersSize <= 0) {
            //wrong size
            return null;
        }
        pointer += SIZE_INT_BYTES;

        int signerSize = Endianness.leBytesToInt(signerBlock, pointer);
        if (signerSize > signersSize || signerSize <= 0) {
            //wrong size
            return null;
        }
        pointer += SIZE_INT_BYTES;

        int signedDataSize = Endianness.leBytesToInt(signerBlock, pointer);
        if (signedDataSize > signerSize || signedDataSize <= 0) {
            //wrong size
            return null;
        }
        pointer += SIZE_INT_BYTES;

        int digestsSize = Endianness.leBytesToInt(signerBlock, pointer);
        if (digestsSize > signedDataSize || digestsSize <= 0) {
            //wrong size
            return null;
        }
        pointer += SIZE_INT_BYTES + digestsSize;

        int certificatesSize = Endianness.leBytesToInt(signerBlock, pointer);
        if (certificatesSize > signerBlock.length || certificatesSize <= 0) {
            //wrong size
            return null;
        }
        pointer += SIZE_INT_BYTES;

        int encodedCertificateSize = Endianness.leBytesToInt(signerBlock, pointer);
        if (encodedCertificateSize > certificatesSize || encodedCertificateSize <= 0) {
            //wrong size
            return null;
        }
        pointer += SIZE_INT_BYTES;

        byte[] data = new byte[encodedCertificateSize];
        System.arraycopy(signerBlock, pointer, data, 0, encodedCertificateSize);

        return data;
    }
}
