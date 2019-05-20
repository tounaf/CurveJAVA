
/*
 * user specification: the function's comment should contain keys as follows: 1. write about the function's comment.but
 * it must be before the "{talendTypes}" key.
 * 
 * 2. {talendTypes} 's value must be talend Type, it is required . its value should be one of: String, char | Character,
 * long | Long, int | Integer, boolean | Boolean, byte | Byte, Date, double | Double, float | Float, Object, short |
 * Short
 * 
 * 3. {Category} define a category for the Function. it is required. its value is user-defined .
 * 
 * 4. {param} 's format is: {param} <type>[(<default value or closed list values>)] <name>[ : <comment>]
 * 
 * <type> 's value should be one of: string, int, list, double, object, boolean, long, char, date. <name>'s value is the
 * Function's parameter name. the {param} is optional. so if you the Function without the parameters. the {param} don't
 * added. you can have many parameters for the Function.
 * 
 * 5. {example} gives a example for the Function. it is optional.
 */

import org.bitcoinj.core.Base58;


//import org.apache.commons.codec.binary.Hex;
//import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;
import java.util.logging.Logger;
import java.util.logging.Level;

public class Curve25519 {

    public Curve25519() throws NoSuchAlgorithmException {
    }

    final private static char[] hexArray = "0123456789abcdef".toCharArray();
    private static final String ENCRYPTION_IV = "4e5Wa71fYoT7MFEX";

    private static String encrypt(String src, String key) {
        //fixKeyLength();
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, makeKey(key), makeIv());
            return Base58.encode(cipher.doFinal(src.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String decrypt(String src, String key) {
        String decrypted = "";
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, makeKey(key), makeIv());
            decrypted = new String(cipher.doFinal(Base58.decode(src)));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            e.printStackTrace();
        }
        return decrypted;
    }

    private static AlgorithmParameterSpec makeIv() {
        try {
            return new IvParameterSpec(ENCRYPTION_IV.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static Key makeKey(String encryptionKey) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] key = md.digest(encryptionKey.getBytes("UTF-8"));
            return new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] savePublicKey(PublicKey key) throws Exception {
        //return key.getEncoded();

        ECPublicKey eckey = (ECPublicKey) key;
        //return eckey.getQ().getEncoded(true);
        return eckey.getQ().getEncoded();
    }

    private static PublicKey loadPublicKey(byte[] data) throws Exception {

        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        ECParameterSpec ecSpec = new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());

        ECPublicKeySpec pubKey = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(data), ecSpec);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return kf.generatePublic(pubKey);
    }

    private static byte[] savePrivateKey(PrivateKey key) throws Exception {
        //return key.getEncoded();

        ECPrivateKey eckey = (ECPrivateKey) key;
        return eckey.getD().toByteArray();
    }

    public static PrivateKey loadPrivateKey(byte[] data) throws Exception {

        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        ECParameterSpec ecSpec = new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());

        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), ecSpec);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return kf.generatePrivate(prvkey);


    }

    private static String doECDH(byte[] dataPrv, byte[] dataPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");

        ka.init(loadPrivateKey(dataPrv));
        ka.doPhase(loadPublicKey(dataPub), true);
        byte[] secret = ka.generateSecret();
        return bytesToHex(secret);
    }

    private static void removeCryptographyRestrictions() {
        Logger logger = Logger.getAnonymousLogger();
        if (!isRestrictedCryptography()) {
            logger.fine("Cryptography restrictions removal not needed");
            return;
        }
        try {
            /*
             * Do the following, but with reflection to bypass access checks:
             *
             * JceSecurity.isRestricted = false;
             * JceSecurity.defaultPolicy.perms.clear();
             * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
             */
            final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
            final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
            final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

            final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
            isRestrictedField.setAccessible(true);
            final Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(isRestrictedField, isRestrictedField.getModifiers() & ~Modifier.FINAL);
            isRestrictedField.set(null, false);

            final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
            defaultPolicyField.setAccessible(true);
            final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

            final Field perms = cryptoPermissions.getDeclaredField("perms");
            perms.setAccessible(true);
            ((Map<?, ?>) perms.get(defaultPolicy)).clear();

            final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            defaultPolicy.add((Permission) instance.get(null));

            logger.fine("Successfully removed cryptography restrictions");
        } catch (final Exception e) {
            logger.log(Level.WARNING, "Failed to remove cryptography restrictions", e);
        }
    }

    private static boolean isRestrictedCryptography() {
        // This matches Oracle Java 7 and 8, but not Java 9 or OpenJDK.
        final String name = System.getProperty("java.runtime.name");
        final String ver = System.getProperty("java.version");
        return name != null && name.equals("Java(TM) SE Runtime Environment")
                && ver != null && (ver.startsWith("1.7") || ver.startsWith("1.8"));
    }

    private static void fixKeyLength() {
        String errorString = "Failed manually overriding key-length permissions.";
        int newMaxKeyLength;
        try {
            /*newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            if (newMaxKeyLength < 256) {*/
            if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
                System.out.println("newMaxKeyLength : " + newMaxKeyLength);
                Class c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
                Constructor con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissionCollection = con.newInstance();
                Field f = c.getDeclaredField("all_allowed");
                f.setAccessible(true);
                f.setBoolean(allPermissionCollection, true);

                c = Class.forName("javax.crypto.CryptoPermissions");
                con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissions = con.newInstance();
                f = c.getDeclaredField("perms");
                f.setAccessible(true);
                ((Map) f.get(allPermissions)).put("*", allPermissionCollection);

                c = Class.forName("javax.crypto.JceSecurityManager");
                f = c.getDeclaredField("defaultPolicy");
                f.setAccessible(true);
                Field mf = Field.class.getDeclaredField("modifiers");
                mf.setAccessible(true);
                mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
                f.set(null, allPermissions);

                newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            }
        } catch (Exception e) {
            throw new RuntimeException(errorString, e);
        }
        if (newMaxKeyLength < 256)
            throw new RuntimeException(errorString); // hack failed*/
    }

    public static String encryptData(String data, String privateKey, String publicKey) throws Exception {

        removeCryptographyRestrictions();

        Security.addProvider(new BouncyCastleProvider());

        PrivateKey PrivateKey = loadPrivateKey(Hex.decode(privateKey));
        PublicKey PublicKey = loadPublicKey(Hex.decode(publicKey));

        byte[] dataPrvA = savePrivateKey(PrivateKey);
        byte[] dataPubB = savePublicKey(PublicKey);

      /*  System.out.println("*************************************Encryption********************************");
        System.out.println("Private Key : " + bytesToHex(dataPrvA));
        System.out.println("Public Key : " + bytesToHex(dataPubB));
        */
        String secret = doECDH(dataPrvA, dataPubB);

        // System.out.println("secret: " + secret);

        String encrypted = encrypt(data, secret);

        return encrypted;

    }

    public static String decryptData(String encrypted, String privateKey, String publicKey) throws Exception {
        //fixKeyLength();
        removeCryptographyRestrictions();
        Security.addProvider(new BouncyCastleProvider());

        PrivateKey PrivateKey = loadPrivateKey(Hex.decode(privateKey));
        PublicKey PublicKey = loadPublicKey(Hex.decode(publicKey));

        byte[] dataPrvA = savePrivateKey(PrivateKey);
        byte[] dataPubB = savePublicKey(PublicKey);
/*
        System.out.println("*************************************Decryption********************************");
        System.out.println("Private Key : " + bytesToHex(dataPrvA));
        System.out.println("Public Key : " + bytesToHex(dataPubB));
  */
        String secret = doECDH(dataPrvA, dataPubB);

        //    System.out.println("secret: " + secret);

        String decrypted = decrypt(encrypted, secret);

        return decrypted;

    }

    public static String sign(String encrypted, String pvtKey) throws Exception {
        PrivateKey PrivateKey = loadPrivateKey(Hex.decode(pvtKey));
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(PrivateKey, new SecureRandom());
        signature.update(encrypted.getBytes());
        byte[] signatureBytes = signature.sign();
        String signatures = bytesToHex(signatureBytes);
        return signatures;
    }

    public static boolean isSignCorrect(String encrypted, String signatures, String pubKey) throws Exception {

        Signature signature = Signature.getInstance("SHA256withECDSA");
        PublicKey PublicKey = loadPublicKey(Hex.decode(pubKey));
        signature.initVerify(PublicKey);
        signature.update(encrypted.getBytes());
        boolean isSigned = signature.verify(Hex.decode(signatures));
        return isSigned;
    }

    public static void main(String args[]) throws Exception {

        removeCryptographyRestrictions();
        Security.addProvider(new BouncyCastleProvider());
        /******* Generating keys **********/
        /*X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        ECParameterSpec ecSpec = new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());

        KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
        kpgen.initialize(ecSpec, new SecureRandom());
        KeyPair pairA = kpgen.generateKeyPair();
        KeyPair pairB = kpgen.generateKeyPair();
        
        PrivateKey PrivateA = pairA.getPrivate();
        PublicKey PublicA = pairA.getPublic();

        PrivateKey PrivateB = pairB.getPrivate();
        PublicKey PublicB = pairB.getPublic();
        
        String privateA = new String(bytesToHex(savePrivateKey(PrivateA)));
        String publicA = new String(bytesToHex(savePublicKey(PublicA)));
        
        String privateB = new String(bytesToHex(savePrivateKey(PrivateB)));
        String publicB = new String(bytesToHex(savePublicKey(PublicB)));


        /********* Encrypt and decrypt with signature ***********/
        //A side's private and public key
        String privateA = "0e5d96f3c9c08b5d971a7a577edd28ec48beaa74fbff8dc039ac99a780c473a7";
        String publicA = "0419487fa5a062dbfe60f0e4417f8f072773c28a4af32c359e0faf79ab850668ae2aef84a126e9f6e4b023d0c948541cad51cd3cf9ac799c16a2cbbb551161fd53";
        //B side's private and public key
        String privateB = "01df5626c604c00cf69cdf5eea1c6bdd146ba547c132d3f20eaa61dce149f009";
        String publicB = "0426f870637896fc3a7bd06efe3dd62914cafad3f207ae4c319a94dec1115fbc215fdfa0e46f0144c71488da908bd3202ae39330425e76ab8210279d5d7e5846a5";

        String session = "<maSessionGenerateRequest>" +
                "<login>%1$s</login>" +
                "<password>%2$s</password>" +
                "<partnerId>%3$s</partnerId>" +
                "</maSessionGenerateRequest>";

        String payement = "<maGENInitiatePaymentRequest>\n" +
                "\n" +
                "<msisdn>%1$s</msisdn>\n" +
                "\n" +
                "<amount>%2$s</amount>\n" +
                "\n" +
                "<id>%3$s</id>\n" +
                "\n" +
                "<sessionID>%4$s</sessionID>\n" +
                "\n" +
                "<ref>%5$s</ref>" +
                "</maGENInitiatePaymentRequest>";

        String data = "";

        if (args.length > 1) {
            if (args[0].equals("payment")) {
                data = String.format(payement, args[1], args[2], args[3], args[4], args[5]);
            } else if (args[0].equals("authentification")) {
                data = String.format(session, args[1], args[2], args[3]);
            }
            //Encrypted with the A private key and the B public key
            String encrypted = encryptData(data, privateA, publicB);


            //sign with the A private key
            String sign = sign(encrypted, privateB);

            System.out.println("<Datacrypt>" + "<Encrypted>" + encrypted + "</Encrypted>" + "<Signature>" + sign + "</Signature>" + "</Datacrypt>");

        } else {
            //Encrypted with the A private key and the B public key
            String encrypted = args[0];


            //sign with the A private key
            String sign = sign(encrypted, privateB);


            //check signature with the A public key
            boolean isSignedCorrect = isSignCorrect(encrypted, sign, publicB);

            if (isSignedCorrect) {

                //Decrypt with the B private key and the A public key
                //encrypted = "7Gs8GiDFZh2xLJps215kCpUTKtF4LCEMdt2aiKyfFHUvWpepzkNo1B3dQ2CYcxZtaEvtScYdxBgmfgWPyzVNTPFfZfvxB4cXJX2ikvMwvhZJuEdfvbPrqaweJukaAqvDy5uYCoSKGD2iAKFQMnSTPxCTcQ2Pva9c53UZtbrffEA5NBjEJB8FaFZM1yGY5uS9ZU1wPwrGjidAons8p2aKS9pKDdL3f74YD2PxUxnrVa8ppETy3Bn4vM9e9UKSfbt9rE7nknR536wSqhwQ2Bb1mLXaE3kPwNz5WpiCY7tpc9koCgtFg6JNLAqCjLEyzptnnfg9GLAS";
                String decrypted = decryptData(encrypted, privateB, publicA);
                System.out.println(decrypted);
            } else {
                // System.out.println("Signature not valid");
            }
        }
//       }
    }
}

