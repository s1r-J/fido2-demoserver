fido2-demoserver
==

FIDO2 Demo Server for [@s1r-J/fido2server-lib]() module.

## Install

1. Clone this repository.

```
$ git clone https://github.com/s1r-J/fido2-demoserver.git
```

2. To use HTTPS, install [mkcert](https://github.com/FiloSottile/mkcert) and create private key and certificate. If you have HTTPS development environment, it can be used.
    2.1. If you don't have, following this entry: [Why and How to Use HTTPS in Your Local Development Environment](https://auth0.com/blog/using-https-in-your-development-environment/)

3. Store private key PEM(default `localhost-key.pem`) and certificate PEM(default `localhost.pem`) in `ssl` folder.
4. Copy from `.env.sample` file to `.env` file.
5. `npm install`

## Usage

1. `npm start`
2. Wait a moment, access `https://localhost:3000` in web browser.

![index](./img/index.png)

In this condition, you can also use [self-conformance test tools](https://fidoalliance.org/certification/functional-certification/conformance/).

Note: Windows Hello maybe not works properly using `https://localhost:3000`. Use other actual domain.

### Customize

Environment variable is in `.env` file.

#### Hostname and Port

If you want to change hostname or port, change `HOSTNAME` or `PORT` in `.env` file.
In that state, for passing self-conformance test replace metadata service data file.

1. Access http://mds.certinfra.fidoalliance.org/ and register new url.
    1.1. For MDS version 3 http://mds3.certinfra.fidoalliance.org/
2. Get endpoints and root certificate.

![mds](./img/mds-endpoints.png)

3. Set endpoints to `MDS2_ENDPOINTS` variable in `scripts/mds.js`.
    3.1. For MDS version 3 `MDS3_ENDPOINTS` variable
4. Set root certificate to `MDS2_ROOTCERT` variable in `scripts/mds.js`.
    4.1. For MDS version 3 `MDS3_ROOTCERT` variable
5. `npm run mds`
6. `fidomds/mds2-<random value>.json` is created.
    6.1. For MDS version 3 `fidomds/mds3-<random value>.json`

## License

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0.html)
