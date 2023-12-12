/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyRep;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Optional;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import com.ibm.crypto.plus.provider.ock.XECKey;
import ibm.security.internal.spec.NamedParameterSpec;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

final class XDHPrivateKeyImpl extends PKCS8Key implements XECPrivateKey, Serializable, Destroyable {

    // Field serialVersionUID per tag [SERIALIZATION] in DesignNotes.txt
    private static final long serialVersionUID = 6034044314589513430L;

    private OpenJCEPlusProvider provider = null;
    private Optional<byte[]> scalar;
    private NamedParameterSpec params;
    BigInteger bi1; // parameter used in FFDHE
    BigInteger bi2; // parameter used in FFDHE
    BigInteger bi3; // parameter used in FFDHE
    private Exception exception = null; // In case an exception happened and the API did
    // not allow us to throw it, we throw it at the end

    private static final byte TAG_PARAMETERS_ATTRS = 0x00;

    private transient boolean destroyed = false;
    private transient XECKey xecKey = null;

    private void setFieldsFromXeckey() throws Exception {
        if (this.key == null) {
            this.key = extractPrivateKeyFromOCK(xecKey.getPrivateKeyBytes()); // Extract key from GSKit and sets params
            this.scalar = Optional.of(key);
            this.algid = XECKey.getAlgId(this.params.getCurve());
        }
    }

    /**
     * Construct a key from an internal XECKey.
     *
     * @param provider
     * @param xecKey
     */
    public XDHPrivateKeyImpl(OpenJCEPlusProvider provider, XECKey xecKey)
            throws InvalidKeyException {
        if (provider == null)
            throw new InvalidKeyException("provider cannot be null");
        if (xecKey == null)
            throw new InvalidKeyException("xecKey cannot be null");
        this.xecKey = xecKey;
        this.provider = provider;
        try {
            setFieldsFromXeckey();
        } catch (Exception e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    /**
     * Construct a key from a DER encoded key.
     *
     * @param provider
     * @param encoded
     */
    public XDHPrivateKeyImpl(OpenJCEPlusProvider provider, byte[] encoded)
            throws InvalidKeyException {
        this.provider = provider;
        try {
            byte[] alteredEncoded = processEncodedPrivateKey(encoded); // Sets params, key, and algid, and alters encoded
            // to fit with GSKit and sets params
            this.xecKey = XECKey.createPrivateKey(provider.getOCKContext(), alteredEncoded,
                    this.params.getCurve());
            this.scalar = Optional.of(this.key);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create XEC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Construct a key from a its scalar parameter.
     *
     * @param provider
     * @param scalar
     * @param params   must be of type NamedParameterSpec
     */
    public XDHPrivateKeyImpl(OpenJCEPlusProvider provider, AlgorithmParameterSpec params,
            Optional<byte[]> scalar) throws InvalidParameterException {

        if (provider == null) {
            throw new InvalidParameterException("provider must not be null");
        }
        // get the internal wrapper instance from input params
        this.params = NamedParameterSpec.getInternalNamedParameterSpec(params);

        try {
            if (XECKey.isFFDHE(this.params.getCurve()))
                throw new InvalidParameterException("FFDHE algorithms are not suppoerted");
        } catch (Exception e) {
            throw new InvalidParameterException(e.getMessage());
        }
        // TODO: figure out how to build FFDHE curves from paramspec

        this.provider = provider;
        this.scalar = scalar;
        if (scalar != null)
            this.key = scalar.get();
        try {
            if (this.key == null)
                this.xecKey = XECKey.generateKeyPair(provider.getOCKContext(),
                        this.params.getCurve());
            else {
                this.algid = XECKey.getAlgId(this.params.getCurve());
                byte[] der = buildOCKPrivateKeyBytes();
                this.xecKey = XECKey.createPrivateKey(provider.getOCKContext(), der,
                        this.params.getCurve());
            }
        } catch (Exception exception) {
            InvalidParameterException ike = new InvalidParameterException(
                    "Failed to create XEC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }

    }

    /**
     * Builds DER from private key to be used to build EVP_PKEY in GSKit
     * DER form: SEQUENCE: SEQUENCE: [INTEGER (version), SEQUENCE[OID], OCTET STRING[OCTET STRING] (private key)
     *
     * @return
     * @throws IOException
     */
    private byte[] buildOCKPrivateKeyBytes() throws IOException {
        DerOutputStream mainSeq = new DerOutputStream();

        // Add first BigInteger (always 0 for XEC/FFDHE)
        mainSeq.putInteger(0);

        // Adding OID
        DerOutputStream oidSeq = new DerOutputStream();
        oidSeq.putOID(this.algid.getOID());
        mainSeq.write(DerValue.tag_Sequence, oidSeq.toByteArray());

        // Adding Key
        DerOutputStream keyOctetString = new DerOutputStream();
        keyOctetString.putOctetString(key);
        mainSeq.putOctetString(keyOctetString.toByteArray());

        // Wrapping up in a sequence
        DerOutputStream outStream = new DerOutputStream();
        outStream.write(DerValue.tag_Sequence, mainSeq);
        return outStream.toByteArray();
    }

    /**
     * Extract and return the private key bytes from the output DER returned from GSKit.
     * The XDH privateKeyBytes format is SEQUENCE: [INTEGER (version), SEQUENCE[OID],
     * OCTET STRING[OCTET STRING(private key)]
     * <p>
     * The FFDHE privateKeyBytes format is SEQUENCE: [INTEGER (version), SEQUENCE[OID,
     * SEQUENCE[INTEGER,INTEGER,INTEGER]], OCTET STRING[INTEGER(private key)]
     * <p>
     * The function also sets the params field
     *
     * @param privateKeyBytes
     * @return
     * @throws IOException
     */
    private byte[] extractPrivateKeyFromOCK(byte[] privateKeyBytes) throws IOException {
        DerInputStream in = new DerInputStream(privateKeyBytes);
        DerValue[] inputValue = in.getSequence(3);

        // Retrieve OID and make sure its an XEC/FFDHE curve
        DerInputStream derInputStream = null;
        if (inputValue.length > 1) {
            derInputStream = inputValue[1].getData();
            try {
                processOIDSequence(derInputStream, null);
            } catch (Exception ex) {
                throw new IOException("This curve does not seem to be an XEC or FFDHE curve", ex);
            }
        }

        // Private key is in the form of an octet string stored inside another octet string
        byte[] privData = null;
        if (inputValue.length > 2) {
            privData = inputValue[2].getOctetString();
            if (this.params.getName().contains("FFDH"))
                privData = new DerInputStream(privData).getBigInteger().toByteArray();
            else
                privData = new DerInputStream(privData).getOctetString();
            return privData;
        }
        return null;
    }

    /**
     * Takes a the OID Sequence part of a DER encoded key
     * Retrieves the curve type from that DER and sets the parameter
     * Retrieves and returns the OID
     * If output stream is present, copy all the retrieved data into it
     *
     * @param oidInputStream
     * @return objectIdentifer
     * @throws IOException
     */
    private ObjectIdentifier processOIDSequence(DerInputStream oidInputStream,
            DerOutputStream outStream) throws IOException {

        ObjectIdentifier oid = oidInputStream.getOID();
        XECKey.checkOid(oid);
        NamedParameterSpec.CURVE curve;
        try { // FFDH curve
            DerValue[] params = oidInputStream.getSequence(3);
            if (params.length >= 3) {
                bi1 = params[0].getBigInteger();
                bi2 = params[1].getBigInteger();
                bi3 = params[2].getBigInteger();
                int size = bi1.bitLength();
                curve = XECKey.getCurve(oid, size);
            } else
                throw new IOException("This curve does not seem to be a valid XEC/FFDHE curve");
        } catch (IOException e) { // XEC curve
            curve = XECKey.getCurve(oid, null);
        }

        if (outStream != null) {
            outStream.putOID(oid);
            if (XECKey.isFFDHE(curve)) {
                DerOutputStream seq = new DerOutputStream();
                seq.putInteger(bi1);
                seq.putInteger(bi2);
                seq.putInteger(bi3);
                outStream.write(DerValue.tag_Sequence, seq.toByteArray());
            }
        }

        this.params = new NamedParameterSpec(curve);
        return oid;
    }

    /**
     * Takes a DER encoded key of the following format: SEQUENCE: [version (INTEGER),
     * OID (OID is inside a sequence of 1 element), private key (OCTET STRING)]
     * Returns a similar DER with the last part of the sequence changed to:
     * OCTETSTRING[OCTETSTRING] (Octet string of an octet string which is the private key)
     * It's weird, no idea why it is this way but that's what GSKIT/OpenSSL accepts
     * <p>
     * The function also sets the params field, algid, and key
     *
     * @param encoded
     * @return
     * @throws IOException
     */
    private byte[] processEncodedPrivateKey(byte[] encoded) throws IOException {
        DerInputStream in = new DerInputStream(encoded);
        DerValue[] inputValue = in.getSequence(3);
        DerOutputStream outStream = new DerOutputStream();

        // Copy version from input DER to new DER
        BigInteger version = inputValue[0].getBigInteger();
        outStream.putInteger(version);

        // Copy OID
        ObjectIdentifier oid = null;
        if (inputValue.length < 3)
            throw new IOException("This curve does not seem to be a valid XEC/FFDHE curve");

        if (inputValue[1].getTag() == DerValue.tag_Sequence) {
            DerInputStream oidInputStream = inputValue[1].toDerInputStream();
            DerOutputStream outputOIDSequence = new DerOutputStream();
            oid = processOIDSequence(oidInputStream, outputOIDSequence);
            this.algid = new AlgorithmId(oid);
            outStream.write(DerValue.tag_Sequence, outputOIDSequence.toByteArray());
        } else
            throw new IOException("Unexpected non sequence while parsing private key bytes");

        // Read, convert, then write private key
        byte[] keyBytes = inputValue[2].getOctetString();
        DerInputStream derStream = new DerInputStream(keyBytes);
        try {
            // XDH private key in SunEC new Java 17 design requires [octet-string[octer-string[key-bytes]]] format,
            // otherwise, it causes interop issue. JCK issue 569
            this.key = derStream.getOctetString(); // Try J17 format [octet-string[octer-string[key-bytes]]]
        } catch (IOException e) {
            this.key = keyBytes; // Try J11 format [octer-string[key-bytes]]
        }
        DerOutputStream encodedKey = new DerOutputStream();
        if (XECKey.isFFDHE(this.params.getCurve())) {
            BigInteger octetStringAsBigInt = new BigInteger(this.key);
            encodedKey.putInteger(octetStringAsBigInt); // Put in another octet string
        } else {
            encodedKey.putOctetString(this.key); // Put in another octet string
        }
        outStream.putOctetString(encodedKey.toByteArray());

        DerOutputStream asn1Key = new DerOutputStream();
        asn1Key.write(DerValue.tag_Sequence, outStream);

        return asn1Key.toByteArray();
    }

    public XECKey getOCKKey() {
        return this.xecKey;
    }

    /**
     * @return external wrapped java documented instance of NamedParameterSpec
     */
    public AlgorithmParameterSpec getParams() {
        return params.getExternalParameter();
    }

    public Optional<byte[]> getScalar() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return scalar;
    }

    public byte[] getKeyBytes() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return this.key.clone();
    }

    @Override
    public AlgorithmId getAlgorithmId() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return super.getAlgorithmId();
    }

    @Override
    public String getAlgorithm() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }

        return "XDH";
    }

    /**
     * Adds a sequence of FFDHE integers (bi1, bi2, and bi3) to the OutputStream param.
     * DER added: SEQUENCE[INTEGER,INTEGER,INTEGER]
     *
     * @param oidBytes the OutputStream on which to write the DER encoding.
     * @throws IOException on encoding errors.
     */
    public static void putFFDHEIntegers(DerOutputStream oidBytes, BigInteger bi1, BigInteger bi2,
            BigInteger bi3) throws IOException {
        DerOutputStream oidSubSeq = new DerOutputStream();
        oidSubSeq.putInteger(bi1);
        oidSubSeq.putInteger(bi2);
        oidSubSeq.putInteger(bi3);
        oidBytes.write(DerValue.tag_Sequence, oidSubSeq.toByteArray());
    }

    /**
     * Encodes this object to an OutputStream.
     *
     * @param os the OutputStream on which to write the DER encoding.
     * @throws IOException on encoding errors.
     */
    public void encode(OutputStream os) throws IOException {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            IOException ike = new IOException("Failed in setFieldsFromXeckey");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }

        DerOutputStream bytes = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();

        // encode the version
        bytes.putInteger(0);

        // encode encryption algorithm
        DerOutputStream oidBytes = new DerOutputStream();
        DerOutputStream oidTmp = new DerOutputStream();
        oidBytes.putOID(algid.getOID());
        switch (this.params.getCurve()) {
            case X25519:
            case X448:
            case Ed25519:
            case Ed448:
                break;
            case FFDHE2048:
                putFFDHEIntegers(oidBytes, bi1, bi2, bi3);
                break;
            case FFDHE3072:
                putFFDHEIntegers(oidBytes, bi1, bi2, bi3);
                break;
            case FFDHE4096:
                putFFDHEIntegers(oidBytes, bi1, bi2, bi3);
                break;
            case FFDHE6144:
                putFFDHEIntegers(oidBytes, bi1, bi2, bi3);
                break;
            case FFDHE8192:
                putFFDHEIntegers(oidBytes, bi1, bi2, bi3);
                break;

        }
        oidTmp.write(DerValue.tag_Sequence, oidBytes);
        bytes.write(oidTmp.toByteArray());

        // encode encrypted key
        if (this.key != null) {
            // XDH private key in SunEC and new Java 17 design requires [octet-string[octer-string[key-bytes]]] format,
            // otherwise, it causes interop issue. JCK issue 569
            bytes.putOctetString(new DerValue(DerValue.tag_OctetString, this.key).toByteArray());
        }

        // wrap everything into a SEQUENCE
        tmp.write(DerValue.tag_Sequence, bytes);

        os.write(tmp.toByteArray());
    }

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException if some error occurs while destroying this key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (exception != null) {
            String msg = exception.getMessage();
            msg += "\nStack:\n";
            for (StackTraceElement s : exception.getStackTrace())
                msg += "- " + s.toString() + "\n";
            throw new DestroyFailedException(
                    "An exception occurred during the execution of this object: " + msg);
        }
        if (!destroyed) {
            destroyed = true;
            if (this.key != null)
                Arrays.fill(this.key, (byte) 0x00);
            this.xecKey = null;
            this.scalar = null;
            this.params = null;
        }
    }

    /**
     * Determines if this key has been destroyed.
     */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed)
            throw new IllegalStateException("This key is no longer valid");
    }

    protected Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.PRIVATE, getAlgorithm(), getFormat(), getEncoded());
    }
}