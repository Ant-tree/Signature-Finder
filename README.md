# Signature-Finder
Finds latest signature schemes from APK file

Core sources are located [here](https://github.com/Ant-tree/Signature-Finder/tree/main/SignatureFinder/app/src/main/java/com/anttree/signaturefinder)

Supports Jar signer & Apk signature scheme 2 & 3

## Usage
Simply call ```findCertSignature``` and it returns ```ArrayList``` of ```SignatureScheme```

```java

String apkPath;

...

ArrayList<SignatureScheme> signatureSchemes = findCertSignature(apkPath);

for(SignatureScheme scheme : signatureSchemes) {
    // 1 for jar signer signature, 2 & 3 for APK signature scheme
    int version = scheme.getSchemeVersion();
    
    // For scheme 2 & 3 : Whole Signature block data.
    // For jar signer (scheme v.1), this returns first RSA | DSA | EC data (alphabetic order)
    byte[] sigBlockData = scheme.getSigBlockData();
    
    // Below is ASN1 encoded format of certificate
    // Convert it into X.509 using CertificateFactory if needed.
    byte[] certificate = scheme.getFirstCertificateData(); 
    ...
}
```
