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
if (typeof ProxyJS.Util == "undefined") ProxyJS.Util = {};


/** From Base64 to asn1
 * @param raw   Text with the Base64 representation
 * @return An ASN1 object
 */
ProxyJS.Util.pem2asn1 = function(raw)
{
    var der = Base64E.unarmor(raw);
    return ASN11.decode(der);
}


/** Datetime as a string in the form yymmddHHMMSSZ
 */
ProxyJS.Util.getUTCDateAsString = function(time) {
	return time.getUTCFullYear().toString().substring(2, 4)
			+ ("0" + (time.getUTCMonth() + 1).toString()).slice(-2)
			+ ("0" + time.getUTCDate().toString()).slice(-2)
			+ ("0" + time.getUTCHours().toString()).slice(-2)
			+ ("0" + time.getUTCMinutes().toString()).slice(-2)
			+ "Z";
}


/** Generate the proxy DN
 */
ProxyJS.Util.getProxyDn = function(userDn)
{
    return userDn + "/CN=" + Number(new Date());
}


ProxyJS.Util.ASN1 = {};


/** Check if the hex TLV is a sequence
 */
ProxyJS.Util.ASN1.isTlvASequence = function(tlv)
{
    return tlv.substr(0, 2) === "30";
}

/** Check if the hex TLV is an OID
 */
ProxyJS.Util.ASN1.isTlvAOid = function(tlv)
{
    return tlv.substr(0, 2) === "06";
}


ProxyJS.Util.X509 = {};


/** Get the extensions from a certificate
 */
ProxyJS.Util.X509.getExtensions = function(certificate)
{
    var pos;
    for (var i = 9; i >= 7; --i) {
        pos = ASN1HEX.getDecendantIndexByNthList(certificate.hex, 0, [0, i]);
        if (typeof pos != "undefined") {
            console.log("Extensions found at [0, " + i + "]");
            var ext = ASN1HEX.getHexOfV_AtObj(certificate.hex, pos);
            if (!ProxyJS.Util.ASN1.isTlvASequence(ext))
                throw "Extensions are not a sequence, probably a bug?";
            return ext;
        }
    }
    return null;
}


/** Get an extension by OID
 */
ProxyJS.Util.X509.getExtensionByOid = function(extensions, oid)
{
    var children = ASN1HEX.getPosArrayOfChildren_AtObj(extensions, 0);
    for (var i = 0; i < children.length; ++i) {
        var pos = children[i];
        var tlv = ASN1HEX.getHexOfTLV_AtObj(extensions, pos);
        if (ProxyJS.Util.ASN1.isTlvASequence(tlv)) {
            var sequence = ASN1HEX.getHexOfV_AtObj(extensions, pos);
            var oid_obj = ASN1HEX.getHexOfTLV_AtObj(sequence, 0);
            if (ProxyJS.Util.ASN1.isTlvAOid(oid_obj)) {
                var foundOid = ASN1HEX.hextooidstr(ASN1HEX.getHexOfV_AtObj(sequence, 0));
                console.log("Found extension '" + foundOid + "'");
                if (foundOid == oid) {
                    return tlv;
                }
            }
        }
    }
    return null;
}

