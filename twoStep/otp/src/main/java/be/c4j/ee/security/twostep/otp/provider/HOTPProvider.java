/*
 * Taken with small modifications
 *
 * Copyright (C) 2004, OATH.  All rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "OATH HOTP Algorithm" in all material
 * mentioning or referencing this software or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as
 *  "derived from OATH HOTP algorithm"
 * in all material mentioning or referencing the derived work.
 *
 * OATH (Open AuTHentication) and its members make no
 * representations concerning either the merchantability of this
 * software or the suitability of this software for any particular
 * purpose.
 *
 * It is provided "as is" without express or implied warranty
 * of any kind and OATH AND ITS MEMBERS EXPRESSaLY DISCLAIMS
 * ANY WARRANTY OR LIABILITY OF ANY KIND relating to this software.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 *
 *
 * Portions Copyrighted [2011] [ForgeRock AS]
 */
package be.c4j.ee.security.twostep.otp.provider;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.twostep.otp.OTPProvider;
import be.c4j.ee.security.twostep.otp.OTPUserData;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

/**
 *
 */
public class HOTPProvider implements OTPProvider {

    private static final String TRUNCATE_OFFSET = "truncate_offset";
    private static final String CHECKSUM = "checksum";

    /**
     * a flag that indicates if a checksum digit
     * <p>
     * M'Raihi, et al. Informational [Page 29]
     * <p>
     * RFC 4226 HOTP Algorithm December 2005
     * <p>
     * should be appended to the OTP.
     */
    private boolean addChecksum = false;
    /**
     * the offset into the MAC result to begin truncation. If this
     * value is out of the range of 0 ... 15, then dynamic truncation
     * will be used. Dynamic truncation is when the last 4 bits of
     * the last byte of the MAC are used to determine the start
     * offset.
     */
    private int truncationOffset = 0;
    private int digits;
    private Properties properties;

    @Override
    public void setProperties(int digits, Properties properties) {
        this.digits = digits;
        this.properties = properties;
    }

    @Override
    public String generate(OTPUserData data) {
        addChecksum = false;
        truncationOffset = 0;

        if (properties.containsKey(CHECKSUM)) {
            addChecksum = Boolean.parseBoolean(properties.get(CHECKSUM).toString());
        }

        if (properties.containsKey(TRUNCATE_OFFSET)) {
            truncationOffset = Integer.parseInt(properties.get(TRUNCATE_OFFSET).toString());
        }

        try {
            Long value = data.getValue();
            if (value == null) {
                value = 0L;
            }
            long base = value + 1;
            data.setValue(base);
            return generateOTP(data.getKey(), base);
        } catch (Exception e) {
            throw new OctopusUnexpectedException(e);
        }

    }

    @Override
    public boolean supportValidate() {
        return true;
    }

    @Override
    public boolean valid(OTPUserData data, int window, String userOTP) {
        boolean result = false;
        for (int i = -window; i < window; i++) {
            if (data.getValue() == null) {
                // This is a developer error, so we can do this.
                throw new IllegalArgumentException("OTPUserData.value needs to contain the latest counter");
            }
            String code = generateOTP(data.getKey(), data.getValue() + i);
            if (code.equals(userOTP)) {
                result = true;
            }
            break;   // TODO Where does this come from and why do we need it?
        }
        return result;
    }

    // These are used to calculate the check-sum digits.
    // 0 1 2 3 4 5 6 7 8 9
    private static final int[] doubleDigits = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};

    /**
     * Calculates the checksum using the credit card algorithm. This algorithm
     * has the advantage that it detects any single mistyped digit and any
     * single transposition of adjacent digits.
     *
     * @param num    the number to calculate the checksum for
     * @param digits number of significant places in the number
     * @return the checksum of num
     */
    private int calcChecksum(long num, int digits) {
        boolean doubleDigit = true;
        int total = 0;
        while (0 < digits--) {
            int digit = (int) (num % 10);
            num /= 10;
            if (doubleDigit) {
                digit = doubleDigits[digit];
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        int result = total % 10;
        if (result > 0) {
            result = 10 - result;
        }
        return result;
    }

    /**
     * This method uses the JCE to provide the HMAC-SHA-1
     * <p>
     * <p>
     * <p>
     * M'Raihi, et al. Informational [Page 28]
     * <p>
     * RFC 4226 HOTP Algorithm December 2005
     * <p>
     * <p>
     * algorithm. HMAC computes a Hashed Message Authentication Code and in this
     * case SHA1 is the hash algorithm used.
     *
     * @param keyBytes the bytes to use for the HMAC-SHA-1 key
     * @param text     the message or text to be authenticated.
     */

    private byte[] hmacSha1(byte[] keyBytes, byte[] text) {
        try {
            Mac hmacSha1;
            try {
                hmacSha1 = Mac.getInstance("HmacSHA1");
            } catch (NoSuchAlgorithmException nsae) {
                hmacSha1 = Mac.getInstance("HMAC-SHA-1");
            }
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmacSha1.init(macKey);
            return hmacSha1.doFinal(text);
        } catch (NoSuchAlgorithmException e) {
            throw new OctopusConfigurationException(e.getMessage());
        } catch (InvalidKeyException e) {
            throw new OctopusConfigurationException(e.getMessage());
        }
    }

    /**
     * This method generates an OTP value for the given set of parameters.
     *
     * @param secret       the shared secret
     * @param movingFactor the counter, time, or other value that changes on a per use
     *                     basis.
     * @return A numeric String in base 10 that includes digits plus the optional checksum digit if requested.
     */
    private String generateOTP(byte[] secret, long movingFactor) {
        StringBuilder result;
        int codeDigits = digits;

        // put movingFactor value into text byte array
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }

        // compute hmac hash
        byte[] hash = hmacSha1(secret, text);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;
        if ((0 <= truncationOffset) && (truncationOffset < (hash.length - 4))) {
            offset = truncationOffset;
        }
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        int otp = binary % ((int) Math.pow(10, codeDigits));
        if (addChecksum) {
            otp = (otp * 10) + calcChecksum(otp, codeDigits);
        }
        result = new StringBuilder(Integer.toString(otp));
        while (result.length() < digits) {
            result.insert(0, "0");
        }
        return result.toString();
    }

}
