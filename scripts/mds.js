import axios from 'axios';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import FM3 from 'fido-mds3';

const MDS2_DATAFILE = 'https://mds.certinfra.fidoalliance.org/getEndpoints';
const MDS2_ROOTCERT = `-----BEGIN CERTIFICATE-----
MIICZzCCAe6gAwIBAgIPBF0rd3WL/GExWV/szYNVMAoGCCqGSM49BAMDMGcxCzAJ
BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF
IE1ldGFkYXRhIFRPQyBTaWduaW5nIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG
QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC
VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh
dGEgVE9DIFNpZ25pbmcgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ
BgcqhkjOPQIBBgUrgQQAIgNiAARcVLd6r4fnNHzs5K2zfbg//4X9/oBqmsdRVtZ9
iXhlgM9vFYaKviYtqmwkq0D3Lihg3qefeZgXXYi4dFgvzU7ZLBapSNM3CT8RDBe/
MBJqsPwaRQbIsGmmItmt/ESNQD6jYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBTd95rIHO/hX9Oh69szXzD0ahmZWTAfBgNVHSMEGDAW
gBTd95rIHO/hX9Oh69szXzD0ahmZWTAKBggqhkjOPQQDAwNnADBkAjBkP3L99KEX
QzviJVGytDMWBmITMBYv1LgNXXiSilWixTyQqHrYrFpLvNFyPZQvS6sCMFMAOUCw
Ach/515XH0XlDbMgdIe2N4zzdY77TVwiHmsxTFWRT0FtS7fUk85c/LzSPQ==
-----END CERTIFICATE-----`;

const MDS3_DATAFILE = 'https://mds3.certinfra.fidoalliance.org/getEndpoints';
const MDS3_ROOTCERT = `-----BEGIN CERTIFICATE-----
MIICaDCCAe6gAwIBAgIPBCqih0DiJLW7+UHXx/o1MAoGCCqGSM49BAMDMGcxCzAJ
BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF
IE1ldGFkYXRhIDMgQkxPQiBST09UIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG
QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC
VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh
dGEgMyBCTE9CIFJPT1QgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ
BgcqhkjOPQIBBgUrgQQAIgNiAASKYiz3YltC6+lmxhPKwA1WFZlIqnX8yL5RybSL
TKFAPEQeTD9O6mOz+tg8wcSdnVxHzwnXiQKJwhrav70rKc2ierQi/4QUrdsPes8T
EirZOkCVJurpDFbXZOgs++pa4XmjYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAfBgNVHSMEGDAW
gBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAKBggqhkjOPQQDAwNoADBlAjEA/xFsgri0
xubSa3y3v5ormpPqCwfqn9s0MLBAtzCIgxQ/zkzPKctkiwoPtDzI51KnAjAmeMyg
X2S5Ht8+e+EQnezLJBJXtnkRWY+Zt491wgt/AwSs5PHHMv5QgjELOuMxQBc=
-----END CERTIFICATE-----`;

(async () => {
    dotenv.config();

    const serverURL = `${process.env.SCHEME}://${process.env.HOSTNAME}:${process.env.PORT}`;

    // Remove
    const fileNames = fs.readdirSync(process.env.FIDO_METADATA_DIR);
    const rmFiles = fileNames.filter(fn => fn.startsWith('mds2-') || fn.startsWith('mds3-'));
    for (const rm of rmFiles) {
        fs.unlinkSync(path.resolve(process.env.FIDO_METADATA_DIR, rm));
    }

    // MDS2
    const mds2Res = await axios.post(MDS2_DATAFILE, {
        endpoint: serverURL,
    });
    const mds2Endpoints = mds2Res.data.result;
    const accessor = FM3.Accessor;
    accessor.setRootCertPem(MDS2_ROOTCERT);
    for (const url of mds2Endpoints) {
        try {
            await accessor.fromUrl(new URL(url));
            const json = accessor.toJsonObject();
            fs.writeFileSync(`./fidomds/mds2-${url.slice(-64)}.json`, JSON.stringify(json['entries']));
            console.log(`Success: ${json['entries'].length}`);
        } catch (err) {
            console.log(url, err.message);
        }
    }

    // MDS3
    const mds3Res = await axios.post(MDS3_DATAFILE, {
        endpoint: serverURL,
    });
    const mds3Endpoints = mds3Res.data.result;
    accessor.setRootCertPem(MDS3_ROOTCERT);
    for (const url of mds3Endpoints) {
        try {
            await accessor.fromUrl(new URL(url));
            const json = accessor.toJsonObject();
            fs.writeFileSync(`./fidomds/mds3-${url.slice(-64)}.json`, JSON.stringify(json['entries']));
            console.log(`Success: ${json['entries'].length}`);
        } catch (err) {
            console.log(url, err.message);
        }
    }

})();

