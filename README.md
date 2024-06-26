# INDIGO Identity and Access Management (IAM) service

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.3496834.svg)](https://doi.org/10.5281/zenodo.3496834)
[![Change Log](https://img.shields.io/github/release/indigo-iam/iam.svg?label=changelog)](https://github.com/indigo-iam/iam/releases/latest)
[![github-build-status](https://github.com/indigo-iam/iam/actions/workflows/maven.yml/badge.svg?branch=master&event=push)](https://github.com/indigo-iam/iam/actions/workflows/maven.yml)
[![sonarqube-qg](https://sonarcloud.io/api/project_badges/measure?project=indigo-iam_iam&metric=alert_status)](https://sonarcloud.io/dashboard?id=indigo-iam_iam)
[![sonarqube-coverage](https://sonarcloud.io/api/project_badges/measure?project=indigo-iam_iam&metric=coverage)](https://sonarcloud.io/dashboard?id=indigo-iam_iam)
[![sonarqube-maintainability](https://sonarcloud.io/api/project_badges/measure?project=indigo-iam_iam&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=indigo-iam_iam)
[![Contributors](https://img.shields.io/github/contributors/indigo-iam/iam.svg)](https://github.com/indigo-iam/iam/graphs/contributors)

The INDIGO IAM is an Identity and Access Management service first developed in the
context of the INDIGO-Datacloud Horizon 2020 project, and currently maintained and
developed by [INFN][infn].

## Main features

- OpenID connect provider based on the [MitreID OpenID connect library][mitreid]
- [SCIM][scim] user provisioning and management APIs
- SAML authentication support
- OIDC authentication support
- X.509 authentication support
- [OAuth token exchange][token-exchange] support

## What's new

See the [changelog](CHANGELOG.md).

## Documentation

See the [IAM documentation][iam-doc].

## Developer guide

See the [contributing](CONTRIBUTING.md) document.

## License

[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

## Acknowledgements

INDIGO IAM developers use [YourKit Java Profiler](http://www.yourkit.com/) to provide useful insights into the performance of this Java application. 
<img src="https://www.yourkit.com/images/yklogo.png" height="24">

[indigo-datacloud]: https://www.indigo-datacloud.eu/ 
[mitreid]: https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server
[scim]: http://www.simplecloud.info/
[token-exchange]: https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-09
[iam-doc]: https://indigo-iam.github.io
[eosc-hub]: https://www.eosc-hub.eu/
[infn]: https://home.infn.it/it/

