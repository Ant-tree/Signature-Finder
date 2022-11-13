package com.anttree.signaturefinder.common;

import static com.anttree.signaturefinder.common.BytesLength.SIZE_INT64_BYTES;
import static com.anttree.signaturefinder.common.BytesLength.SIZE_INT_BYTES;

public class Endianness {

    public static int leBytesToInt(byte[] target, int ofIndex)
    {
        return (int) leBytesToNum(target, ofIndex, SIZE_INT_BYTES);
    }

    public static long leBytesToLong(byte[] target, int ofIndex)
    {
        return leBytesToNum(target, ofIndex, SIZE_INT64_BYTES);
    }

    public static long leBytesToNum(byte[] target, int ofIndex, int size)
    {
        long result = 0;
        for (int index = 0; index < size; index++)
        {
            result |= (long)(target[ofIndex + index] & 0xFF) << index * 8;
        }
        return result;
    }
}
