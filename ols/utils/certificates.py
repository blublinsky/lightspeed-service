"""Certificates handling utility functions."""

import logging
import os
import shutil
from pathlib import Path

import certifi
from cryptography import x509

import ols.app.models.config as config_model
from ols import constants
from ols.src.auth.k8s import K8sClientSingleton


def add_ca_to_certificates_store(
    logger: logging.Logger, cert_path: Path, cert_location: str
) -> None:
    """Add a certificate to the certifi store."""
    logger.debug("Certifications store location: %s", cert_location)
    logger.info("Adding certificate '%s' to certificates store", cert_path)

    # load certificate file that needs to be added into store
    with open(cert_path, "rb") as certificate_file:
        new_certificate_data = certificate_file.read()
    new_cert = x509.load_pem_x509_certificate(new_certificate_data)

    # load existing certificates
    with open(cert_location, "rb") as certifi_store:
        certifi_certs_data = certifi_store.read()
    certifi_certs = x509.load_pem_x509_certificates(certifi_certs_data)

    # append the certificate to the certificates store
    if new_cert in certifi_certs:
        logger.warning("Certificate '%s' is already in certificates store", cert_path)
    else:
        with open(cert_location, "ab") as certifi_store:
            certifi_store.write(new_certificate_data)
            logger.debug(
                "Written certificate with length %d bytes", len(new_certificate_data)
            )
    # Getting and adding kube-root certificates
    logger.info("Adding kube-root certificate to certificates store", cert_path)
    v1_client = K8sClientSingleton.get_corev1api_client()
    # get certs string. Note that here we are hard coding name and namespace of the config map
    # check this if we will change namespace that we are using
    cert_string = v1_client.read_namespaced_config_map(
        name="kube-root-ca.crt", namespace="openshift-lightspeed"
    ).data["ca.crt"]
    # split certificates string
    certs_array = cert_string.split("-----BEGIN CERTIFICATE-----")
    certs = [
        "-----BEGIN CERTIFICATE-----" + certs_array[i]
        for i in range(1, len(certs_array))
    ]
    # open store file
    with open(cert_location, "ab") as certifi_store:
        for cert_data in certs:
            # for every certificate
            cert_bytes = cert_data.encode("utf-8")  # convert cert strin to bytes
            cert = x509.load_pem_x509_certificates(cert_bytes)  # convert cert data
            # append the certificate to the certificates store
            if cert in certifi_certs:
                logger.warning(
                    "Certificate '%s' is already in certificates store", cert_data
                )
                continue
            # put certificate into the store
            certifi_store.write(cert_bytes)
            logger.debug("Written certificate with length %d bytes", len(cert_bytes))


def generate_certificates_file(
    logger: logging.Logger, ols_config: config_model.OLSConfig
) -> None:
    """Generate certificates by merging certificates from certify with defined certificates."""
    certificate_directory = ols_config.certificate_directory

    if certificate_directory is None:
        logger.warning(
            "Cannot generate certificate file: certificate directory is not specified"
        )
        return

    logger.info("Generating certificates file into directory %s", certificate_directory)

    # file where all certificates will be stored
    destination_file = os.path.join(
        certificate_directory, constants.CERTIFICATE_STORAGE_FILENAME
    )

    certifi_cert_location = certifi.where()
    logger.debug(
        "Copying certifi certificates file from %s into %s",
        certifi_cert_location,
        destination_file,
    )

    shutil.copyfile(certifi_cert_location, destination_file)

    for certificate_path in ols_config.extra_ca:
        add_ca_to_certificates_store(logger, certificate_path, destination_file)
