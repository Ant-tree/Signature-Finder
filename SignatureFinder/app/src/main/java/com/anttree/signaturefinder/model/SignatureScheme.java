package com.anttree.signaturefinder.model;

import androidx.annotation.IntRange;
import androidx.annotation.Nullable;

/**
 * SignatureScheme that contains scheme version with
 * raw signature block data (bytes) and first certificate data
 * First certificate data represents the very first certificate from
 * first signer (if multiple signers are involved)
 *
 * Can only parse scheme version 2 and 3,
 * as such scheme version 1 must be parsed using other strategy or API.
 *
 * sigBlockData = BLOCK DATA
 * +-----------------------+------------------------+----------------------------------+
 * |  SCHEME_ID (4 bytes)  |  BLOCK_SIZE (4 bytes)  |   BLOCK DATA (BLOCK_SIZE bytes)  |
 * +-----------------------+------------------------+----------------------------------+
 * */
public class SignatureScheme {

    public static final int SCHEME_V1 = 1;
    public static final int SCHEME_V2 = 1;
    public static final int SCHEME_V3 = 1;

    private final int schemeVersion;
    private final byte[] sigBlockData;
    private final byte[] firstCertificateData;

    public SignatureScheme(@IntRange(from = 1, to = 3) int schemeVersion
            , @Nullable byte[] sigBlockData
            , @Nullable byte[] firstCertificateData)
    {
        this.schemeVersion = schemeVersion;
        this.sigBlockData = sigBlockData;
        this.firstCertificateData = firstCertificateData;
    }

    /* Scheme version of current signature scheme */
    public int getSchemeVersion()
    {
        return schemeVersion;
    }

    /* Whole SigBlock data of single Scheme */
    public byte[] getSigBlockData()
    {
        return sigBlockData;
    }

    /* Get First certificate from signers block, even if there's multiple certificates */
    public byte[] getFirstCertificateData()
    {
        return firstCertificateData;
    }
}