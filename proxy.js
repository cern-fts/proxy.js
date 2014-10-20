/*
 *  Copyright 2014 CERN
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
**/


if (typeof ProxyJS == "undefined") ProxyJS = {};


/** Get the subject key identifier
 */
ProxyJS.getSubjectKeyIdentifier = function(certificate)
{
    var extensions = ProxyJS.Util.X509.getExtensions(certificate);
    if (!extensions)
        return null;
    var skid_seq = ProxyJS.Util.X509.getExtensionByOid(extensions, "2.5.29.14");
    if (!skid_seq)
        return null;
    var skid_os = ASN1HEX.getDecendantHexVByNthList(skid_seq, 0, [1]);
    return skid_os.substr(4); // Skip type (04) and lenght
}


/** Sign the request
 * @param request       ASN11 object containing the request
 * @param userDn        User"s DN
 * @param certificate   X509 object containing the user's public certificate
 * @param privateKey    RSAKey object with the user"s private key
 * @return A PEM encoded signed proxy
 */
ProxyJS.signRequest = function(request, userDn, certificate, privateKey, lifetime)
{
    if (!request instanceof ASN11)
        throw "request is not an instance of ASN11";
    if (!certificate instanceof X509)
        throw "certificate is not an instance of X509";
    if (!privateKey instanceof RSAKey)
        throw "privateKey is not an instance of RSAKey";
    if (typeof lifetime !== "number")
        throw "lifetime is not an integer";
    if (lifetime < 1)
        throw "lifetime must be at least 1 hour";


    var proxyPublicKey = request.getCSRPubKey();
    var proxyPublicRSA = new RSAKey();
    proxyPublicRSA.setPublic(
        proxyPublicKey.modulus.replace(/ /g, ""),
        proxyPublicKey.exponent.replace(/ /g, "")
    );

    // Validate certificate and private key modulus
    if (privateKey.n.compareTo(certificate.subjectPublicKeyRSA.n) != 0) {
        throw "The RSA private key modulus and the public certificate modulus do not match!";
    }

    // Create to-be-signed certificate and initialize
    var tbsc = new KJUR.asn1.x509.TBSCertificate();

    tbsc.setSerialNumberByParam({
        "int" : certificate.getSerialNumberHex()
    });
    tbsc.setSignatureAlgByParam({
        "name" : "SHA1withRSA"
    });
    tbsc.setIssuerByParam({
        "str" : userDn
    });
    tbsc.asn1Issuer.hTLV = certificate.getSubjectHex();

    tbsc.setSubjectByParam({
        "str" : ProxyJS.Util.getProxyDn(userDn)
    });
    tbsc.setSubjectPublicKeyByParam({
        "rsakey" : proxyPublicRSA
    });

    // Validity
    var notBefore = new Date();
    notBefore.setUTCHours(notBefore.getUTCHours());
    tbsc.setNotBeforeByParam({
        "str" : ProxyJS.Util.getUTCDateAsString(notBefore)
    });
    var notAfter = new Date();
    notAfter.setUTCHours(notAfter.getUTCHours() + lifetime);
    console.log("Proxy will expire the " + lifetime);
    tbsc.setNotAfterByParam({
        "str" : ProxyJS.Util.getUTCDateAsString(notAfter)
    });

    // Extensions
    tbsc.appendExtension(new KJUR.asn1.x509.BasicConstraints({"cA": false, "critical": true}));
    // 101 to set "Digital Signature, Key Encipherment". 0 means disabled "Non Repudiation"
    tbsc.appendExtension(new KJUR.asn1.x509.KeyUsage({"bin":"101", "critical":true}));

    var subjectKeyId = ProxyJS.getSubjectKeyIdentifier(certificate);
    console.log("Subject key identifier: "+ subjectKeyId);
    var paramAKI = {"kid": {"hex": subjectKeyId}, "issuer": certificate.getIssuerHex(), "critical": false};
    tbsc.appendExtension(new KJUR.asn1.x509.AuthorityKeyIdentifier(paramAKI));

    // RFC 3820 extensions
    tbsc.appendExtension(new ProxyJS.ProxyCertInfo({
        "critical": true, "limited": true, "length": 0
    }));

    // Sign
    var cert = new KJUR.asn1.x509.Certificate({
        "tbscertobj" : tbsc,
        "rsaprvkey" : privateKey,
        "prvkey" : privateKey,
        "rsaprvpas" : "empty"
    });
    cert.sign();

    return cert;
}

