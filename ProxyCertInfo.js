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


/** ProxyCertInfo extension
 * See RFC3820
 * http://www.ietf.org/rfc/rfc3820.txt
 */
ProxyJS.ProxyCertInfo = function(params) {
    ProxyJS.ProxyCertInfo.superclass.constructor.call(this, params);
    this.limited = false;
    this.path_length = 0;
    
    this.getExtnValueHex = function() {
        var a = new Array();
        var policy = new Array();
        
        if (this.limited)
            policy.push(new KJUR.asn1.DERObjectIdentifier({"oid": "1.3.6.1.5.5.7.21.2"}));
        else
            policy.push(new KJUR.asn1.DERObjectIdentifier({"oid": "1.3.6.1.5.5.7.21.1"}));
        
        a.push(new KJUR.asn1.DERInteger({"int": this.path_length}));
        a.push(new KJUR.asn1.DERSequence({"array": policy}));
        
        var asn1Seq = new KJUR.asn1.DERSequence({"array": a});
        this.asn1ExtnValue = asn1Seq;
        return this.asn1ExtnValue.getEncodedHex();
    };
    
    this.oid = "1.3.6.1.5.5.7.1.14";
    
    if (typeof params != "undefined") {
        if (typeof params["limited"] != "underfined")
            this.limited = params["limited"];
        if (typeof params["length"] != "undefined")
            this.path_length = params["length"];
    }
};
YAHOO.lang.extend(ProxyJS.ProxyCertInfo, KJUR.asn1.x509.Extension);

