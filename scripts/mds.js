import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import FM3 from 'fido-mds3';

const MDS2_ENDPOINTS = [
    'https://mds.certinfra.fidoalliance.org/execute/07b381474f76fc9eb8745711134149b24f8444cb1bf3b1c979c1d1dadef87694',
    'https://mds.certinfra.fidoalliance.org/execute/1fc5f22a684a7d4b9cac2f5834601eeec6325e1ff282c5ee5a3f81b16de80425',
    'https://mds.certinfra.fidoalliance.org/execute/3c3455e233d916cafca702c5eb91db71fb3d9914a2729864e8bf5fc9f15d5e5c',
    'https://mds.certinfra.fidoalliance.org/execute/8f337946d3c17507112f2b79a44d5c80c753ba7ece5715d3426f7aca4bc2216d',
    'https://mds.certinfra.fidoalliance.org/execute/dc9ced3424d60c1680a70fb6d53e282862f59628c00105480bc0a38f4f2d694c',
];
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

const MDS3_ENDPOINTS = [
    'https://mds3.certinfra.fidoalliance.org/execute/122e38d260f0b01f4ef79f40d5d24abc7a08542e6e646b27d4acd1f0d396d74b',
    'https://mds3.certinfra.fidoalliance.org/execute/611a4a29a37c64716b36b3e18fd5b907d014bbc8b23f4a6a98e9851231c9308a',
    'https://mds3.certinfra.fidoalliance.org/execute/654be5eb1aa76357fdc740164c8055e147fc51292a315a4b587c8f7c22376e9e',
    'https://mds3.certinfra.fidoalliance.org/execute/88f2139c04cc1ba4ee9c97c68359e72d02d2b11e960a8e22534f1c6461e0a8a4',
    'https://mds3.certinfra.fidoalliance.org/execute/a765baf5403ea14ae51ab29d3c0f133f9302d174cc463c99bf5e30a03ed5aa02',
];
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

    // Remove
    const fileNames = fs.readdirSync(process.env.FIDO_METADATA_DIR);
    const rmFiles = fileNames.filter(fn => fn.startsWith('mds2-') || fn.startsWith('mds3-'));
    for (const rm of rmFiles) {
        fs.unlinkSync(path.resolve(process.env.FIDO_METADATA_DIR, rm));
    }

    // MDS2
    const accessor = FM3.Accessor;
    accessor.setRootCertPem(MDS2_ROOTCERT);
    for (const url of MDS2_ENDPOINTS) {
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
    const accessor = FM3.Accessor;
    accessor.setRootCertPem(MDS3_ROOTCERT);
    for (const url of MDS3_ENDPOINTS) {
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

